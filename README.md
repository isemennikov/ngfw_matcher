# ngfw_matcher
Checking whether the input matches the rules on PT NGFW

# ngfw-match

CLI-инструмент симуляции трафика для **PT NGFW**.  
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
ngfw_matcherer/
├── __main__.py         # Точка входа: python -m ngfw_matcherer
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

*** !!! Внимание!!! Перед использованием приложения, рекомендовано использовать RO УЗ в СУ PT NGFW. ***  
Для этого необходимо создать УЗ с ролью *** Operator ***

*** Запуск***

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

## Команды

Структура вызова: **общие флаги** идут до команды, **флаги команды** — после.

```bash
python -m ngfw_matcher --host URL --user LOGIN --pass PWD  КОМАНДА  [флаги команды]
```

### test-connection

Проверяет подключение и авторизацию, выводит лог каждого шага и список доступных Device Groups.

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret test-connection
```

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

### match

Основная команда — симуляция трафика по правилам.

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match --src 192.168.1.10 --dst 10.0.0.5 --dport 443 --proto tcp
```

---

## Все режимы команды match

### 1. Одиночный запрос

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match \
  --src 192.168.1.10 \
  --dst 10.0.0.5 \
  --dport 443 \
  --proto tcp \
  --verbose
```

### 2. Параметры --src и --dst

Принимают одно значение — хост, сеть или `any`:

```bash
--src 192.168.1.10        # конкретный хост
--src 192.168.1.0/24      # сеть — совпадение если правило пересекается с /24
--src 10.0.0.0/8          # работает с любым префиксом /0 … /32
--src any                 # любой источник (0.0.0.0/0)
# Несколько source-адресов
match --src 10.0.0.5,172.16.1.1,192.168.5.0/24 --dst 10.43.16.0/24 --dport 443 --proto tcp




--dst 10.0.0.5
--dst 10.0.0.0/16
--dst any
# Несколько destination-адресов  
match --src 10.31.69.23 --dst 10.43.16.36,10.43.16.100,10.43.17.0/24 --dport 5432 --proto tcp

# Несколько и src и dst
match --src 10.99.38.40/29,10.99.38.24/29 --dst 10.43.16.0/24 --dport 636,3268,3269 --proto tcp
```

Логика сравнения с сетями в правиле:
- хост vs сеть правила → `host in network` # хост/сеть + суперсеть в которую входят хост/сеть

```bash
match --src 10.44.16.65  --dst any --dport any  --proto tcp 

```
- сеть vs сеть правила → `overlaps()` (любое пересечение)

```bash
match --src 10.44.16.65  --dst any --dport any  --proto tcp --overlaps
```

### 3. Параметр --dport

Поддерживает несколько форматов. При нескольких портах каждый проверяется отдельно и выводится своя строка результата.

```bash
# Одиночный порт
--dport 443

# Список — проверяет каждый порт отдельно
--dport 80,443,8080

# Диапазон
--dport 5000-5322

# Mix
--dport 80,443,5000-5010,8080-8090

# Any порт
--dport any
```

### 4. Batch-режим

```bash
python -m ngfw_matcher --host https://10.1.31.100 --user admin --pass secret \
  match --device 019e41c1-... --batch traffic.csv --output results.csv
```

Формат `traffic.csv` (заголовок обязателен):
```csv
src_ip,dst_ip,dst_port,protocol,src_port,zone_src,zone_dst
192.168.1.10,10.0.0.5,443,tcp,0,LAN,DMZ
10.10.0.50,8.8.8.8,53,udp,1024,INTERNAL,INTERNET
```

Обязательные колонки: `src_ip, dst_ip, dst_port, protocol`  
Опциональные: `src_port, zone_src, zone_dst`

### 5. Интерактивный режим

Правила загружаются один раз, затем вводишь запросы в цикле без повторной авторизации.

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

### 6. Через backend (кэш ngfw-manager)

```bash
python -m ngfw_matcher \
  --source backend --backend-host https://ngfw-manager.corp \
  --user admin --pass secret \
  match --device 019e41c1-... --batch traffic.csv
```

### 7. Оффлайн-режим

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

Параметры match:
  --source MODE        ngfw (по умолч.) | backend
  --backend-host URL   URL ngfw-manager (при --source backend)
  --device ID          deviceGroupId (иначе — интерактивный выбор)

  Трафик:
  --src IP/CIDR/any    Source: 192.168.1.10 | 10.0.0.0/8 | any
  --dst IP/CIDR/any    Destination
  --dport PORTS        Порт(ы): 443 | 80,443 | 5000-5322 | 80,5000-5010 | any
  --proto PROTO        tcp | udp | icmp | any
  --sport PORT         Source port (опц.)
  --zone-src ZONE      Зона источника (опц.)
  --zone-dst ZONE      Зона назначения (опц.)

  Режим:
  --interactive / -i   Цикл ввода трафика
  --batch FILE.csv     Batch из CSV
  --verbose / -v       Подробный вывод полей правила

  Вывод:
  --output FILE.csv    Сохранить результаты в CSV
  --save-rules FILE    Сохранить правила в JSON
  --log-level          DEBUG | INFO | WARNING | ERROR

  Оффлайн:
  --rules-file FILE    Правила из локального JSON
  --objects-file FILE  Объекты из локального JSON
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