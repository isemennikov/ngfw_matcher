
# ngfw-matcher

CLI-инструмент симуляции трафика и анализа политики **PT NGFW**.  
На вход — `src_ip dst_ip dst_port protocol`, на выход — совпавшее правило,
действие и список **теневых / дублирующих правил**.

Два источника данных (приоритет задаётся флагом `--source`):

| Источник | Флаг | Описание |
|----------|------|----------|
| **ngfw** | `--source ngfw` *(умолчание)* | Прямой PT NGFW API — **актуальные** данные |
| **backend** | `--source backend` | REST API ngfw-manager — кэш PostgreSQL |

---

## Требования

- Python **3.10+**
- Нет сторонних зависимостей (только stdlib)

---

## Структура пакета

```
ngfw_matcher/
├── __main__.py         # Точка входа: python -m ngfw_matcher
├── core/
│   ├── models.py       # TrafficFlow, NormalizedRule, MatchResult
│   ├── resolver.py     # Раскрытие объектов → IP-сети / порты
│   └── matcher.py      # Движок матчинга (first-match)
├── sources/
│   ├── ngfw_api.py     # Источник #1: прямой PT NGFW API v2
│   └── backend_api.py  # Источник #2: ngfw-manager REST API
└── cli/
    ├── main.py         # CLI (argparse, оркестрация)
    └── output.py       # Цветной вывод + экспорт CSV
```

---

## Быстрый старт

**!!! Внимание!!!** Перед использованием приложения, рекомендовано использовать **RO УЗ в СУ PT NGFW**.  
Для этого необходимо создать УЗ с ролью **Operator**

**Запуск**

Приложение следует запускать в диретории выше /ngfw_matcher. Например 

```bash
 /User/Documents/HERE/ngfw_matcher
 ```

```bash
git clone <repo>
cd "PT NGFW"   # родительская папка, содержащая ngfw_matcher/

# Проверка подключения
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret test-connection

# Через SSH-туннель (пробросить порт заранее: ssh -N -L 3663:10.1.31.100:443 user@jump)
python -m ngfw_matcher --host https://localhost:3663 --user admin --pass secret test-connection

# Одиночный запрос
python -m ngfw_matcher \
    --host https://10.1.31.100 --user admin --pass secret \
    match --src 192.168.1.10 --dst 10.0.0.5 --dport 443 --proto tcp
```

Вывод:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Трафик: 192.168.1.10 → 10.0.0.5:443 [TCP]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Allow HTTPS to DMZ
     Позиция   : #8 в наборе pre  (глобальная #12)
     UUID      : a1b2c3d4-...
     Действие  : ALLOW
     Включено  : да

  ⚠  Теневые / дублирующие правила ниже: (1 шт.)
     [#1 в default] Allow All Web  →  ALLOW  (глобальная #45)
       → Эти правила никогда не сработают — кандидаты на удаление.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### Команды

#### test-connection

Проверяет подключение и авторизацию, выводит лог каждого шага и список доступных Device Groups.

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret test-connection
```

Вывод:
```
  ✓  TCP соединение          10.1.31.100:443 — ОК
  ✓  TLS рукопожатие         TLSv1.3
  ✓  POST /api/v2/Login       Set-Cookie [Authorization]: eyJhbGci…
  ✓  POST /api/v2/GetDeviceGroupsTree  API доступен
  ✓  Список групп устройств   найдено: 2

  Доступные группы устройств:

     #  deviceGroupId                           Путь / Имя
  ────────────────────────────────────────────────────────────────
     1  01983ce1-33d8-71b0-a7c9-a5a11e5104a4   Global
     2  019e41c1-3474-73a7-b5ab-62938491fde4   generator
```

---

#### match

Основная команда — симуляция трафика по правилам. Структура параметров:

```bash
python -m ngfw_matcher --host HTTPS://... --user ... --pass ... \
  match [ПАРАМЕТРЫ ТРАФИКА] [РЕЖИМЫ] [ВЫВОД]
```

##### Режимы: Одиночный запрос

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match \
  --src 192.168.1.10 \
  --dst 10.0.0.5 \
  --dport 443 \
  --proto tcp \
  --verbose
```

##### Параметры трафика: --src и --dst

Принимают одно значение — хост, сеть или `any`:

```bash
--src 192.168.1.10        # конкретный хост
--src 192.168.1.0/24      # сеть — совпадение если правило пересекается с /24
--src 10.0.0.0/8          # работает с любым префиксом /0 … /32
--src any                 # любой источник (0.0.0.0/0)

# Несколько source-адресов
match --src 10.0.0.5,172.16.1.1,192.168.5.0/24 --dst 10.43.16.0/24 --dport 443 --proto tcp

# Несколько destination-адресов  
match --src 10.31.69.23 --dst 10.43.16.36,10.43.16.100,10.43.17.0/24 --dport 5432 --proto tcp

# Несколько и src и dst
match --src 10.99.38.40/29,10.99.38.24/29 --dst 10.43.16.0/24 --dport 636,3268,3269 --proto tcp
```

Логика сравнения с сетями в правиле:
- хост vs сеть правила → `host in network` (хост/сеть + суперсеть в которую входят хост/сеть)
- сеть vs сеть правила → `overlaps()` (любое пересечение)

```bash
match --src 10.44.16.65  --dst any --dport any  --proto tcp --overlap
```

##### Параметр --dport

Поддерживает несколько форматов. При нескольких портах каждый проверяется отдельно и выводится своя строка результата.

```bash
--dport 443              # Одиночный порт
--dport 80,443,8080      # Список — проверяет каждый порт отдельно
--dport 5000-5322        # Диапазон
--dport 80,443,5000-5010,8080-8090  # Mix
--dport any              # Any порт
```

##### Режимы: Batch-режим

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match --device 019e41c1-... --batch traffic.csv --output results.csv
```

Формат `traffic.csv` (заголовок обязателен):
```csv
src_ip,dst_ip,dst_port,protocol
192.168.1.10,10.0.0.5,443,tcp
10.10.0.50,8.8.8.8,53,udp
```

Обязательные колонки: `src_ip, dst_ip, dst_port, protocol`

##### Режимы: --fullview

Раскрывает группы в выводе matched/shadowed правил прямо в терминале (усечение до 5 объектов):

```bash
match --src 10.44.16.65 --dst 10.43.16.5 --dport 443 --proto tcp --fullview
```

С дополнительным JSON-сканом всех правил по src:

```bash
match --src 10.44.16.65 --dst any --dport any --proto tcp \
  --fullview --output result.json
```

`result.json` содержит все правила где данный src совпал, с полным раскрытием полей destination и service (включая содержимое групп).

##### Режимы: Интерактивный режим

Правила загружаются один раз, затем вводишь запросы в цикле без повторной авторизации:

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match --device 019e41c1-... --interactive
```

```
traffic> 192.168.1.10 10.0.0.5 443 tcp
traffic> 10.1.2.3 8.8.8.8 53 udp 1024 LAN WAN
traffic> rules          ← показать список всех правил
traffic> help
traffic> q
```

##### Режимы: Backend (кэш ngfw-manager)

```bash
python -m ngfw_matcher \
  --source backend --backend-host https://ngfw-manager.corp \
  --user admin --pass secret \
  match --device 019e41c1-... --batch traffic.csv
```

##### Режимы: Оффлайн-режим

Сохранить правила локально:
```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match --device 019e41c1-... --save-rules rules.json \
  --src 1.1.1.1 --dst 2.2.2.2 --dport 80 --proto tcp
```

Работать без подключения:
```bash
python -m ngfw_matcher match --rules-file rules.json --interactive
```

##### Параметры match: Полный список

```
  --source MODE        ngfw (по умолч.) | backend
  --backend-host URL   URL ngfw-manager (при --source backend)
  --device ID          deviceGroupId (иначе — интерактивный выбор)

  Трафик:
  --src IP/CIDR/any    Source: 192.168.1.10 | 10.0.0.0/8 | any
                       Несколько через запятую: 10.0.0.1,192.168.1.0/24
  --dst IP/CIDR/any    Destination (аналогично --src)
  --dport PORTS        Порт(ы): 443 | 80,443 | 5000-5322 | 80,5000-5010 | any
  --proto PROTO        tcp | udp | icmp | any

  Режим:
  --fullview           Раскрыть группы в выводе matched/shadowed правил.
                       С --output FILE.json — дополнительно сохраняет JSON-скан
                       всех правил, совпадающих по src.
  --overlap            Нестрогий матчинг: включает правила с подсетями запроса
  --interactive / -i   Цикл ввода трафика
  --batch FILE.csv     Batch из CSV
  --verbose / -v       Подробный вывод полей правила

  Вывод:
  --output FILE        Сохранить результаты (CSV для match, JSON для --fullview)
  --save-rules FILE    Сохранить правила в JSON
  --log-level          DEBUG | INFO | WARNING | ERROR

  Оффлайн:
  --rules-file FILE    Правила из локального JSON
  --objects-file FILE  Объекты из локального JSON
```

---

#### find-rule

Поиск правил по имени (подстрока), UUID или **явно прописанному порту**. Выводит карточку с раскрытием всех полей.

```bash
# По части имени
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  find-rule dns --device 019e41c1-...

# По UUID
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  find-rule 01993d88-c005-79bf-8e6b-5dcdcab8828a --device 019e41c1-...

 Все правила с явным портом 179 (BGP) — из снапшота, без API
python -m ngfw_match find-rule --dport 179 --snapshot state.json

# Порт + протокол + фильтр по имени
python -m ngfw_match find-rule bgp --dport 179 --proto tcp --snapshot state.json  

# С экспортом в JSON
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  find-rule allow_dc --device 019e41c1-... --output found.json
```

Вывод:
```
┌─────────────────┬──────────────────────────────────────────────────────┐
│ Имя             │ allow_dc_out_dns                                      │
│ UUID            │ 01993d88-c005-79bf-8e6b-5dcdcab8828a                 │
│ Действие        │ ALLOW                                                 │
│ Статус          │ включено                                              │
│ Набор/Позиция   │ PRE  #25  (глобальная #49)                           │
├─────────────────┼──────────────────────────────────────────────────────┤
│ Source          │ [группа] netgr__all__bank_nets                        │
│                 │   ├─ 10.44.16.0/24                                    │
│                 │   └─ 10.99.38.0/29                                    │
├─────────────────┼──────────────────────────────────────────────────────┤
│ Destination     │ [группа] netgr__all__dns                              │
│                 │   ├─ 10.43.16.36/32                                   │
│                 │   └─ 10.43.16.37/32                                   │
├─────────────────┼──────────────────────────────────────────────────────┤
│ Service         │ ANY                                                   │
├─────────────────┼──────────────────────────────────────────────────────┤
│ Application     │ dns  [0197fb01-...]                                   │
└─────────────────┴──────────────────────────────────────────────────────┘
```

Параметры find-rule:
```
  PATTERN_OR_UUID      Подстрока имени (регистронезависимо) или полный UUID
  --device ID          deviceGroupId
  --output FILE.json   Сохранить найденные правила в JSON
  --rules-file FILE    Оффлайн-режим
```

---

#### rule-hits

Счётчики срабатываний правил (`hits`) из `ListMetricsRulesStats` — с цветной шкалой.  
По умолчанию — порядок как в СУ. `--sort-hits` — сначала самые активные.

```bash
# Все правила устройства
python -m ngfw_matcher --host https://localhost:3663 --user admin --pass secret \
  rule-hits --device 019e41c1-...

# Фильтр по имени + сортировка по убыванию hits
python -m ngfw_matcher --host https://localhost:3663 --user admin --pass secret \
  rule-hits --device 019e41c1-... --rule "default" --sort-hits
```

Вывод:
```
  Правило                                    Hits                        
  ─────────────────────────────────────────────────────────────────────
  Allow HTTPS outbound                       8.4M  ██████████████████████
  Allow DNS queries                          3.1M  ████████░░░░░░░░░░░░░░
  Block Tor exit nodes                       890K  ██░░░░░░░░░░░░░░░░░░░░
  Legacy backup rule (UNUSED)                   0  ░░░░░░░░░░░░░░░░░░░░░░

  █ низкие  █ средние  █ высокие
  Правил: 4   Суммарно hits: 12.4M
```

Параметры rule-hits:
```
  --device ID          deviceGroupId (иначе — интерактивный выбор)
  --rule PATTERN       Фильтр по имени (подстрока, регистронезависимо)
  --sort-hits          Сортировать по убыванию hits
  --batch-size N       Размер батча к API (по умолчанию: 30)
```

### snapshot

Сохраняет полное состояние политики в один JSON-файл для офлайн-анализа.  
В отличие от `--save-rules`, рекурсивно раскрывает все сетевые и сервисные группы —
анализ без сети даёт точные результаты без fallback к `ANY`.

```bash
# Создать снапшот
python -m ngfw_match --host https://10.1.31.100 --user admin --pass secret \
  snapshot --device 019e41c1-... --out state.json

# Работать офлайн (--host не нужен)
python -m ngfw_match match        --snapshot state.json --src 10.0.0.1 --dst 8.8.8.8 --dport 443 --proto tcp
python -m ngfw_match check-shadowed --snapshot state.json
python -m ngfw_match find-rule "allow_http" --snapshot state.json
```


---

#### check-shadowed

Математический анализ теневых правил без задания конкретного трафика.  
Для каждой пары правил (A выше B) проверяет: `A.src ⊇ B.src` И `A.dst ⊇ B.dst` И `A.svc ⊇ B.svc`.  
Если все условия выполнены — B гарантированно теневое. Особо помечает конфликты действий (ALLOW перекрывает DENY).

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  check-shadowed --device 019e41c1-... --output shadows.json
```

Вывод:
```
═══════════════════════════════════════════════════════════════════════
  АНАЛИЗ ТЕНЕВЫХ ПРАВИЛ
═══════════════════════════════════════════════════════════════════════
  Найдено теневых правил    : 12
  Конфликтов действий       : 2
═══════════════════════════════════════════════════════════════════════

  ⚠ КОНФЛИКТ  #41 [pre] deny_legacy_access  →  DENY
              ← перекрывается  #5 [pre] allow_dc_out  →  ALLOW

     #25 [pre] allow_dc_dns  →  ALLOW
      ← перекрывается  #3 [pre] allow_all_internal  →  ALLOW
```

Параметры check-shadowed:
```
  --device ID          deviceGroupId
  --output FILE.json   Сохранить результаты анализа в JSON
  --rules-file FILE    Оффлайн-режим
```



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

Параметры match:
  --source MODE        ngfw (по умолч.) | backend
  --backend-host URL   URL ngfw-manager (при --source backend)
  --device ID          deviceGroupId (иначе — интерактивный выбор)

  Трафик:
  --src IP/CIDR/any    Source: 192.168.1.10 | 10.0.0.0/8 | any
                       Несколько через запятую: 10.0.0.1,192.168.1.0/24
  --dst IP/CIDR/any    Destination (аналогично --src)
  --dport PORTS        Порт(ы): 443 | 80,443 | 5000-5322 | 80,5000-5010 | any
  --proto PROTO        tcp | udp | icmp | any

  Режим:
  --fullview           Раскрыть группы в выводе matched/shadowed правил.
                       С --output FILE.json — дополнительно сохраняет JSON-скан
                       всех правил, совпадающих по src.
  --overlap            Нестрогий матчинг: включает правила с подсетями запроса
  --interactive / -i   Цикл ввода трафика
  --batch FILE.csv     Batch из CSV
  --verbose / -v       Подробный вывод полей правила

  Вывод:
  --output FILE        Сохранить результаты (CSV для match, JSON для --fullview)
  --save-rules FILE    Сохранить правила в JSON
  --log-level          DEBUG | INFO | WARNING | ERROR

  Оффлайн:
  --rules-file FILE    Правила из локального JSON
  --objects-file FILE  Объекты из локального JSON

Параметры find-rule:
  PATTERN_OR_UUID      Подстрока имени (регистронезависимо) или полный UUID (необязательно)
  --dport PORT[-PORT]  Фильтр по dst-порту: только правила с явным указанием порта
  --proto PROTO        Протокол для --dport: tcp | udp | icmp | any (по умолчанию any)
  --device ID          deviceGroupId
  --output FILE.json   Сохранить найденные правила в JSON
  --rules-file FILE    Оффлайн-режим

Параметры check-shadowed:
  --device ID          deviceGroupId
  --output FILE.json   Сохранить результаты анализа в JSON
  --rules-file FILE    Оффлайн-режим
```

---

## Как работает загрузка данных и матчинг

Все данные загружаются **один раз** при старте и хранятся в памяти. Матчинг происходит полностью локально без обращений к API.

```
Шаг 1.  POST /api/v2/Token
        Авторизация — 1 запрос, получаем Bearer token.

Шаг 2.  POST /api/v2/ListVirtualContexts
        Получаем список виртуальных контекстов для выбора Device Group — 1 запрос.

Шаг 3.  POST /api/v2/ListSecurityRules2  (precedence=PRE)
        POST /api/v2/ListSecurityRules2  (precedence=default)
        POST /api/v2/ListSecurityRules2  (precedence=POST)
        Загрузка всех правил с пагинацией по 1000 — 3+ запросов.
        Все правила сохраняются в память как единый список.

Шаг 4.  Матчинг — никаких запросов к API.
        Перебор правил в памяти: PRE → default → POST.
        Первое совпавшее = результат, все последующие совпавшие = теневые правила.

Шаг 5.  POST /api/v2/GetNetworkObjectGroup  — только при встрече networkGroup
        POST /api/v2/GetServiceGroup         — только при встрече serviceGroup
        Каждая группа запрашивается максимум один раз и кэшируется.
        Повторные обращения к той же группе — из кэша, без запроса к API.
```

**Потребление памяти:** ~2–5 KB на правило. 432 правила ≈ 2–3 MB. Несущественно.

**Скорость матчинга:** доли секунды даже для тысяч правил — чистый Python в памяти.

---

## Как работает матчинг правил

Для каждого трафик-запроса правила перебираются сверху вниз (PRE → default → POST). Правило считается совпавшим если **все** условия выполнены одновременно:

1. `src_ip` пересекается с полем `sourceAddr` правила (или `sourceAddr = any`)
2. `dst_ip` пересекается с полем `destinationAddr` правила (или `destinationAddr = any`)
3. `protocol + dst_port` входит в `service` правила (или `service = any`)
4. Зоны совпадают (проверяется только если зоны заданы и в трафике, и в правиле)

Поля `sourceAddr`, `destinationAddr`, `service` могут содержать **несколько объектов** — хостов, сетей, диапазонов, групп. Совпадение с любым из них засчитывается.

**Первое совпавшее правило** = результат (именно так работает файрвол).  
**Все последующие совпавшие** = теневые правила — они никогда не сработают и являются кандидатами на удаление или пересмотр.

**Позиции в выводе:**
- `#8 в наборе pre` — позиция как в веб-интерфейсе СУ (отдельная нумерация для каждого набора PRE / default / POST)
- `глобальная #15` — реальный порядок срабатывания (PRE целиком, затем default, затем POST)

---

## Адаптация

Если PT NGFW использует нестандартный путь API — по умолчанию используется `/api/v2`. Можно передать явно:

```bash
--host https://10.1.31.100/api/v2    # явный путь — используется как есть
--host https://10.1.31.100           # без пути — добавляется /api/v2 автоматически
--host https://localhost:3663        # SSH-туннель — аналогично
```