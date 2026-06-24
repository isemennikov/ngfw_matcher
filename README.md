# ngfw-matcher

CLI-инструмент симуляции трафика и анализа политики **PT NGFW**.  
На вход — `src_ip dst_ip dst_port protocol`, на выход — совпавшее правило, действие и список теневых правил.

Дополнительные режимы: поиск правил по имени/UUID (`find-rule`), анализ теневых правил (`check-shadowed`), счётчики срабатываний (`rule-hits`).

> **Внимание:** рекомендуется использовать RO учётную запись (роль **Operator**) в СУ PT NGFW.

---

## Системные требования

- Python 3.11+
- Docker (для контейнерного запуска)
- Пакеты системы `curl`/`wget` по необходимости
- Для работы с PT NGFW: доступный URL контроллера и учётные данные с правами чтения

## Запуск

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

## Docker

```bash
# Собрать образ из текущей директории
docker build -t ngfw_matcher .

# Запустить контейнер и пробросить порт 8080
docker run --rm -p 8080:8080 ngfw_matcher
```

При запуске через Docker приложение будет доступно на `http://localhost:8080`.

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
  --fullview           Раскрыть группы в выводе + JSON-скан всех правил по src
  --interactive / -i   Цикл ввода трафика без повторной авторизации
  --batch FILE.csv     Batch из CSV (колонки: src_ip, dst_ip, dst_port, protocol)
  --verbose / -v       Подробный вывод полей правила

  Вывод:
  --output FILE        Сохранить результаты (CSV для match, JSON для --fullview)
  --save-rules FILE    Сохранить правила в JSON
  --rules-file FILE    Офлайн-режим (устаревший)
  --objects-file FILE  Объекты из локального JSON

Параметры find-rule:
  PATTERN_OR_UUID      Подстрока имени (регистронезависимо) или полный UUID
  --device ID          deviceGroupId
  --snapshot FILE.json Офлайн-режим
  --output FILE.json   Сохранить найденные правила в JSON

Параметры check-shadowed:
  --device ID          deviceGroupId
  --snapshot FILE.json Офлайн-режим
  --partial            Режим частичного пересечения (overlapping src/dst/svc)
  --output FILE.json   Сохранить результаты анализа в JSON

Параметры rule-hits:
  --device ID          deviceGroupId (иначе — интерактивный выбор)
  --rule PATTERN       Фильтр по имени (подстрока, регистронезависимо)
  --sort-hits          Сортировать по убыванию hits
  --batch-size N       Размер батча к API (по умолчанию: 30)
```
