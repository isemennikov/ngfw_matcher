# Developed by Ilya Semennikov
"""
Источник данных #2: ngfw-manager backend (кэш PostgreSQL).
Используется как fallback, если прямой NGFW API недоступен,
или явно через --source backend.

ngfw-manager (ваше FastAPI-приложение) предоставляет следующие эндпоинты:
    GET /api/rules?device_id=...&ruleset=...    → { rules: [...] }
    GET /api/objects?device_id=...              → { network: [...], services: [...] }
    GET /api/devices                            → [{ id, name, su_id, ... }]

    Также поддерживаем вариант с токеном сессии (cookie-based auth):
    POST /api/login  { username, password }

Если у вас другие пути — адаптируйте константы _API_* ниже.
"""
from __future__ import annotations
import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import Optional

from ..core.models import NormalizedRule

log = logging.getLogger("ngfw.source.backend")

# ── Пути ngfw-manager API ────────────────────────────────────────────────────
_LOGIN_PATH   = "/api/login"
_DEVICES_PATH = "/api/devices"
_RULES_PATH   = "/api/rules"       # ?device_id=...&ruleset=pre|default|post
_OBJECTS_PATH = "/api/objects"     # ?device_id=...

# Альтернативные пути (попробуем если основные вернут 404)
_ALT_RULES_PATH   = "/api/cached-rules"
_ALT_OBJECTS_PATH = "/api/cached-objects"


class NGFWBackendSource:
    """
    Клиент к REST API ngfw-manager.
    Получает уже кэшированные данные из PostgreSQL (таблицы cached_rules, cached_objects).
    """

    def __init__(self, host: str, username: str = "", password: str = "",
                 token: Optional[str] = None, verify_ssl: bool = False):
        self.host       = host.rstrip("/")
        self.username   = username
        self.password   = password
        self.token      = token
        self.verify_ssl = verify_ssl
        self._session_cookie: Optional[str] = None

        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    # ─── HTTP ────────────────────────────────────────────────────────────────

    def _req(self, method: str, url: str, body=None) -> tuple[int, dict | list]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self._session_cookie:
            headers["Cookie"] = self._session_cookie

        data = json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:
                # Сохраняем session cookie если есть
                cookie = resp.headers.get("Set-Cookie")
                if cookie:
                    self._session_cookie = cookie.split(";")[0]
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            return e.code, {"_error": raw[:400]}
        except Exception as e:
            raise ConnectionError(f"Backend request failed [{method} {url}]: {e}") from e

    def _get(self, path: str) -> dict | list:
        url = self.host + path
        status, data = self._req("GET", url)
        if status == 404:
            raise FileNotFoundError(f"404 Not Found: {path}")
        if status >= 400:
            raise RuntimeError(f"GET {path} → HTTP {status}: {data.get('_error','')[:200]}")
        return data

    # ─── Авторизация ─────────────────────────────────────────────────────────

    def login(self) -> None:
        if self.token:
            return  # уже есть токен

        url = self.host + _LOGIN_PATH
        status, data = self._req("POST", url, {
            "username": self.username,
            "password": self.password,
        })

        if status not in (200, 201):
            raise RuntimeError(
                f"Backend login failed: HTTP {status}: {data.get('_error', data)}"
            )

        tok = (data.get("token") or data.get("access_token")
               or data.get("accessToken") or (data.get("data") or {}).get("token"))
        if tok:
            self.token = tok

        log.info("Backend login OK")

    # ─── Устройства ───────────────────────────────────────────────────────────

    def get_devices(self) -> list[dict]:
        data = self._get(_DEVICES_PATH)
        items = data.get("devices", data.get("data", data)) if isinstance(data, dict) else data
        return items if isinstance(items, list) else []

    # ─── Правила ─────────────────────────────────────────────────────────────

    def get_rules(self, device_id: str) -> list[NormalizedRule]:
        normalized: list[NormalizedRule] = []
        global_index = 0

        for ruleset in ("pre", "default", "post"):
            raw_rules = self._fetch_rules_for_ruleset(device_id, ruleset)
            log.info("Backend ruleset %-8s → %d rules", ruleset, len(raw_rules))
            for raw in raw_rules:
                nr = self._normalize_rule(raw, global_index, ruleset)
                normalized.append(nr)
                global_index += 1

        return normalized

    def _fetch_rules_for_ruleset(self, device_id: str, ruleset: str) -> list[dict]:
        # Пробуем основной путь
        for path_tpl in (_RULES_PATH, _ALT_RULES_PATH):
            path = f"{path_tpl}?device_id={device_id}&ruleset={ruleset}"
            try:
                data = self._get(path)
                # Несколько возможных форматов ответа ngfw-manager:
                items = (data.get("rules")
                         or data.get("data")
                         or data.get("items")
                         or data)
                if isinstance(items, list):
                    return items
            except FileNotFoundError:
                continue
            except Exception as e:
                log.warning("Backend rules fetch failed (%s, %s): %s", path, ruleset, e)

        # Пробуем получить все правила без разбивки по ruleset
        try:
            path = f"{_RULES_PATH}?device_id={device_id}"
            data = self._get(path)
            all_rules = (data.get("rules") or data.get("data") or data.get("items") or data)
            if isinstance(all_rules, list):
                # фильтруем по ruleset если поле есть
                filtered = [r for r in all_rules
                            if r.get("ruleset", r.get("policy_type", ruleset)) == ruleset]
                return filtered if filtered else (all_rules if ruleset == "default" else [])
        except Exception as e:
            log.warning("Backend all-rules fetch failed: %s", e)

        return []

    def _normalize_rule(self, raw: dict, index: int, ruleset: str) -> NormalizedRule:
        uid  = (raw.get("id") or raw.get("uuid") or raw.get("rule_id")
                or raw.get("ruleId") or str(index))
        name = (raw.get("name") or raw.get("rule_name") or raw.get("ruleName")
                or f"CachedRule-{index}")

        enabled = raw.get("enabled", raw.get("is_enabled", raw.get("isEnabled", True)))
        if isinstance(enabled, str):
            enabled = enabled.lower() not in ("false", "disabled", "0")

        action_raw = str(raw.get("action") or raw.get("rule_action") or "deny")
        if "ALLOW" in action_raw.upper() or action_raw.lower() in ("permit", "accept", "allow"):
            action = "allow"
        elif "DROP" in action_raw.upper():
            action = "drop"
        else:
            action = "deny"

        prec_raw = raw.get("_precedence") or raw.get("precedence") or raw.get("ruleset") or ruleset
        if "PRE" in str(prec_raw).upper():
            precedence = "pre"
        elif "POST" in str(prec_raw).upper():
            precedence = "post"
        else:
            precedence = "default"

        return NormalizedRule(
            index            = index,
            uid              = uid,
            name             = name,
            enabled          = bool(enabled),
            action           = action,
            precedence       = precedence,
            source_addr      = raw.get("sourceAddr") or raw.get("sources") or raw.get("source"),
            destination_addr = raw.get("destinationAddr") or raw.get("destinations") or raw.get("destination"),
            service          = raw.get("service") or raw.get("services"),
            source_zone      = raw.get("sourceZone") or raw.get("src_zones"),
            destination_zone = raw.get("destinationZone") or raw.get("dst_zones"),
            application      = raw.get("application"),
            raw              = raw,
        )

    # ─── Объекты ─────────────────────────────────────────────────────────────

    def get_network_objects(self, device_id: str) -> dict[str, dict]:
        return self._fetch_objects(device_id, "network")

    def get_service_objects(self, device_id: str) -> dict[str, dict]:
        return self._fetch_objects(device_id, "service")

    def _fetch_objects(self, device_id: str, kind: str) -> dict[str, dict]:
        objects: dict[str, dict] = {}

        for path_tpl in (_OBJECTS_PATH, _ALT_OBJECTS_PATH):
            path = f"{path_tpl}?device_id={device_id}"
            try:
                data = self._get(path)
                # Формат: { "network": [...], "services": [...] }
                # или { "objects": { "network": [...] } }
                if isinstance(data, dict):
                    items = (data.get(kind)
                             or data.get(f"{kind}s")
                             or (data.get("objects") or {}).get(kind)
                             or [])
                    if isinstance(items, list):
                        for obj in items:
                            uid = (obj.get("id") or obj.get("uuid")
                                   or obj.get("object_id") or obj.get("objectId"))
                            if uid:
                                objects[uid] = obj
                        log.info("Backend: loaded %d %s objects", len(objects), kind)
                        return objects
            except FileNotFoundError:
                # Попробуем путь с type-параметром
                try:
                    p2 = f"{path_tpl}?device_id={device_id}&type={kind}"
                    data = self._get(p2)
                    items = data.get("data", data) if isinstance(data, dict) else data
                    if isinstance(items, list):
                        for obj in items:
                            uid = obj.get("id") or obj.get("uuid")
                            if uid:
                                objects[uid] = obj
                        return objects
                except Exception:
                    pass
            except Exception as e:
                log.warning("Backend objects fetch failed: %s", e)

        return objects