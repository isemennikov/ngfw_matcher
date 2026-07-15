# ngfw-matcher

Инструмент анализа праивил на PT NGFW 

---

## Требования

- **Docker** и **Docker Compose** — для запуска приложения в контейнере
- **Python 3.11+** — для локального запуска CLI (без Docker)

---

## Запуск

### Через Docker Compose (рекомендуется)

**Запуск приложения:**

```bash
docker-compose up -d
```

Веб-интерфейс будет доступен по адресу **http://localhost:8080**

**Просмотр логов:**

```bash
docker-compose logs -f web
```

**Выключение приложения:**

```bash
docker-compose down
```

**Удаление образа (полная очистка):**

```bash
docker-compose down --rmi all
```

### Локально (без Docker)

Запускать из директории **выше** папки `ngfw_matcher/`:

```bash
# Проверка подключения
python -m ngfw_matcher --host https://10.1.31.100 --user adminro --pass secret test-connection

# Симуляция трафика
python -m ngfw_matcher --host https://10.1.31.100 --user adminro --pass secret \
  match --src 192.168.1.10 --dst 10.0.0.5 --dport 443 --proto tcp

# Офлайн (без подключения к СУ)
python -m ngfw_matcher match --snapshot state.json \
  --src 192.168.1.10 --dst 10.0.0.5 --dport 443 --proto tcp
```

---

## Все параметры

```
Общие (до команды):
  --host URL           Адрес СУ: https://10.1.31.100 или https://localhost:3663
  --user LOGIN         Логин
  --pass PWD           Пароль
  --token TOKEN        Bearer-токен (вместо логина/пароля)
  --verify-ssl         Проверять TLS-сертификат
  --log-level          DEBUG | INFO | WARNING | ERROR

Команды:
  test-connection      Проверить подключение и показать Device Groups
  match                Симулировать трафик по правилам
  find-rule            Найти правило по имени или UUID
  check-shadowed       Найти теневые (перекрытые) правила
  rule-hits            Счётчики срабатываний правил
  fullview             Все правила, затрагивающие адрес (src или dst)
  nat-audit            Просмотр NAT правил с типом и адресами трансляции

Параметры match:
  --device ID          deviceGroupId (иначе — интерактивный выбор)
  --snapshot FILE.json Офлайн-режим: загрузить правила из снапшота

  Трафик:
  --src IP/CIDR/any    Source: 192.168.1.10 | 10.0.0.0/8 | any
                       Несколько через запятую: 10.0.0.1,192.168.1.0/24
  --dst IP/CIDR/any    Destination (аналогично --src)
  --dport PORTS        Порт(ы): 443 | 80,443 | 5000-5322 | 80,5000-5010 | any
  --proto PROTO        tcp | udp | icmp | icmpv6 | any

  Режим:
  --overlap            Нестрогий матчинг: включает правила с подсетями запроса
  --interactive / -i   Цикл ввода трафика без повторной авторизации
  --batch FILE.csv     Batch из CSV (колонки: src_ip, dst_ip, dst_port, protocol)
  --verbose / -v       Подробный вывод полей правила

  Вывод:
  --output FILE.json   Экспорт результатов в JSON (matched + shadowed)
  --save-rules FILE    Сохранить правила в JSON
  --rules-file FILE    Офлайн-режим (устаревший)
  --objects-file FILE  Объекты из локального JSON

Параметры find-rule:
  PATTERN_OR_UUID      Подстрока имени (регистронезависимо) или полный UUID
  --device ID          deviceGroupId
  --snapshot FILE.json Офлайн-режим
  --dport PORTS        Фильтр по порту
  --proto PROTO        Фильтр по протоколу
  --output FILE.json   Экспорт найденных правил в JSON с раскрытыми объектами

Параметры check-shadowed:
  --device ID          deviceGroupId
  --snapshot FILE.json Офлайн-режим
  --partial            Режим частичного пересечения (overlapping src/dst/svc)
  --output FILE.json   Экспорт результатов анализа в JSON

Параметры fullview:
  --src IP/CIDR[,...]  Искать во всех правилах по sourceAddr
  --dst IP/CIDR[,...]  Искать во всех правилах по destinationAddr
  --dport PORTS        Дополнительный фильтр по порту
  --proto PROTO        Дополнительный фильтр по протоколу
  --overlap            Overlap-режим (нестрогое пересечение)
  --device ID          deviceGroupId
  --snapshot FILE.json Офлайн-режим
  --output FILE.json   Экспорт всех найденных правил в JSON с раскрытыми объектами

Параметры rule-hits:
  --device ID          deviceGroupId (иначе — интерактивный выбор)
  --rule PATTERN       Фильтр по имени (подстрока, регистронезависимо)
  --sort-hits          Сортировать по убыванию hits
  --batch-size N       Размер батча к API (по умолчанию: 30)
```

---

## NAT правила

```bash
# Все NAT правила из снапшота
python -m ngfw_matcher nat-audit --snapshot state.json

# Только SNAT
python -m ngfw_matcher nat-audit --snapshot state.json --type snat

# Только DNAT
python -m ngfw_matcher nat-audit --snapshot state.json --type dnat

# Из живого устройства
python -m ngfw_matcher --host https://10.1.31.100 --user adminro --pass secret \
  nat-audit --device 0197fb01-2707-79e8-95d1-70c78c6fd104
```

Вывод показывает для каждого правила:

- Тип (`SNAT` / `DNAT` / `SNAT+DNAT`) и направление (`-->` / `<--` / `<-->`)
- Условия матчинга: Src, Dst, Svc
- Адреса трансляции: серые (private) `-->` белые (public) для SNAT, и наоборот для DNAT
- Ассоциированные правила безопасности с индикатором покрытия (`[full]` / `[partial]` / `[!narrower:svc]`)

```bash
# Экспорт полного анализа (все NAT + ассоциированные правила безопасности) в JSON
python -m ngfw_matcher nat-audit --snapshot state.json --json nat_audit.json

# Экспорт только DNAT в stdout (для pipe / jq)
python -m ngfw_matcher nat-audit --snapshot state.json --type dnat --json -
```

```text
Параметры nat-audit:
  --device ID          deviceGroupId
  --snapshot FILE.json Офлайн-режим
  --type snat|dnat|all Фильтр по типу NAT (по умолчанию: all)
  --json FILE|-        Экспорт результатов в JSON (- для stdout)
```

---

## Экспорт результатов в JSON

Все команды поддерживают флаг `--output FILE.json`. JSON содержит метаданные инструмента, параметры запроса и раскрытые объекты (адреса, сервисы).

```bash
# Экспорт результатов match
python -m ngfw_matcher --host https://10.1.31.100 --user adminro --pass secret \
  match --src 10.31.102.5 --dst 8.8.8.8 --dport 443 --proto tcp \
  --output match_result.json

# Офлайн-режим: экспорт match из снапшота
python -m ngfw_matcher match --snapshot state.json \
  --src 10.31.102.5 --dst 8.8.8.8 --dport 443 --proto tcp \
  --output match_result.json

# Экспорт find-rule
python -m ngfw_matcher find-rule --snapshot state.json NETBANK \
  --output found_rules.json

# Экспорт find-rule с фильтром по порту
python -m ngfw_matcher find-rule --snapshot state.json BGP \
  --dport 179 --proto tcp --output bgp_rules.json

# Экспорт теневых правил
python -m ngfw_matcher check-shadowed --snapshot state.json \
  --output shadows.json

# Экспорт теневых (режим частичного пересечения)
python -m ngfw_matcher check-shadowed --snapshot state.json \
  --partial --output shadows_partial.json

# Экспорт fullview по src-адресу
python -m ngfw_matcher fullview --snapshot state.json \
  --src 10.31.102.5,10.108.102.5 --output fullview_src.json

# Экспорт fullview по dst с фильтром порта
python -m ngfw_matcher fullview --snapshot state.json \
  --dst 8.8.8.8 --dport 443 --proto tcp --output fullview_dst.json
```
