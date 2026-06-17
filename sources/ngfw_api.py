# Developed by Ilya Semennikov
"""
Источник данных #1: прямой PT NGFW API v2.

BASE_URL строится из --host:
    https://10.1.31.100            →  https://10.1.31.100/api/v2
    https://10.1.31.100/api/v2     →  https://10.1.31.100/api/v2  (уже готово)
    https://localhost:3223         →  https://localhost:3223/api/v2  (туннель)
    https://localhost:3223/api/v2  →  https://localhost:3223/api/v2  (туннель)

Все запросы — POST на {BASE_URL}/{Operation} с JSON-телом.
"""
from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import Optional

log = logging.getLogger("ngfw.source.ngfw_api")

PAGE_SIZE = 1000


class NGFWDirectSource:

    def __init__(
        self,
        host:       str,
        username:   str,
        password:   str,
        token:      Optional[str] = None,
        verify_ssl: bool = False,
    ):
        host = host.rstrip("/")

        # Если URL уже содержит /api/... — берём как BASE_URL напрямую.
        # Иначе добавляем /api/v2.
        if "/api/" in host:
            self.base_url = host
        else:
            self.base_url = f"{host}/api/v2"

        self.username   = username
        self.password   = password
        self.token      = token
        self.verify_ssl = verify_ssl

        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode    = ssl.CERT_NONE

        self._net_group_cache: dict[str, list] = {}
        self._svc_group_cache: dict[str, list] = {}
        self._session_cookie:  Optional[str]   = None  # для Login (cookie-based auth)

    # ─── HTTP ─────────────────────────────────────────────────────────────────

    def _post(self, operation: str, body: dict) -> tuple[dict | list, dict]:
        """
        POST {base_url}/{operation}.
        Возвращает (parsed_body, response_headers).
        Заголовки нужны для перехвата Set-Cookie при Login.
        """
        url     = f"{self.base_url}/{operation}"
        headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self._session_cookie:
            headers["Cookie"] = self._session_cookie

        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:
                raw      = resp.read()
                resp_hdrs = dict(resp.headers)
                parsed   = json.loads(raw) if raw else {}
                return parsed, resp_hdrs
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {e.code} [{operation}]: {raw[:400]}") from e
        except Exception as e:
            raise ConnectionError(f"Ошибка соединения [{operation}]: {e}") from e

    # ─── Авторизация ──────────────────────────────────────────────────────────

    # Варианты авторизации — пробуем по порядку до первого успеха.
    # Каждый элемент: (операция, тело_запроса, режим)
    # Режим "token"  — ищем accessToken в JSON-ответе
    # Режим "cookie" — используем Set-Cookie из заголовка ответа
    _AUTH_ATTEMPTS = [
        ("Token", lambda u, p: {"grantType": "password", "username": u, "password": p}, "token"),
        ("Login", lambda u, p: {"login": u, "password": p}, "cookie"),
        ("Token", lambda u, p: {"username": u, "password": p}, "token"),
    ]

    def login(self) -> str:
        """Пробует все известные варианты авторизации, возвращает токен или маркер куки."""
        if self.token:
            return self.token
        last_err = None
        for operation, make_body, mode in self._AUTH_ATTEMPTS:
            body = make_body(self.username, self.password)
            try:
                resp, hdrs = self._post(operation, body)

                if mode == "token":
                    # Стандартный OAuth2: токен в теле ответа
                    tok = (resp.get("accessToken") or resp.get("access_token")
                           or resp.get("token"))
                    if tok:
                        self.token = tok
                        log.info("Авторизация через %s (Bearer token)", operation)
                        return tok
                    last_err = RuntimeError(
                        f"{operation}: HTTP 200 но токена нет. Ключи: {list(resp.keys()) if isinstance(resp, dict) else type(resp).__name__}"
                    )

                elif mode == "cookie":
                    # PT NGFW /Login возвращает JWT в куке Authorization=eyJ...
                    cookie_hdr = (hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or "")
                    if cookie_hdr:
                        name_val   = cookie_hdr.split(";")[0].strip()
                        if "=" in name_val:
                            cookie_name, cookie_val = name_val.split("=", 1)
                            if cookie_name.strip().lower() in ("authorization", "token", "access_token"):
                                # Токен прямо в куке — используем как Bearer
                                self.token = cookie_val.strip()
                                self._session_cookie = None
                            else:
                                self._session_cookie = name_val
                                self.token = f"session:{cookie_val[:20]}"
                        log.info("Авторизация через %s (cookie → Bearer)", operation)
                        return self.token
                    last_err = RuntimeError(
                        f"{operation}: HTTP 200 но Set-Cookie отсутствует. "
                        f"Заголовки: {[k for k in hdrs if 'cookie' in k.lower() or 'auth' in k.lower()]}"
                    )

            except RuntimeError as e:
                last_err = e
                log.debug("Попытка %s не удалась: %s", operation, e)
                continue
        raise RuntimeError(str(last_err))

    def test_connection(self) -> dict:
        """Расширенная проверка — лог каждого шага."""
        import socket
        from urllib.parse import urlparse

        steps  = []
        result = {"base_url": self.base_url, "steps": steps,
                  "auth": False, "api_reached": False, "token_prefix": None}

        def step(name, ok, detail=""):
            steps.append({"step": name, "ok": ok, "detail": detail})

        # Шаг 1: TCP
        parsed = urlparse(self.base_url)
        host   = parsed.hostname
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.close()
            step("TCP соединение", True, f"{host}:{port} — ОК")
        except Exception as e:
            step("TCP соединение", False, str(e))
            return result

        # Шаг 2: TLS
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=5),
                server_hostname=host
            ) as ss:
                ver = ss.version()
            step("TLS рукопожатие", True, ver)
        except Exception as e:
            step("TLS рукопожатие", False, str(e))
            return result

        # Шаги 3–N: варианты авторизации
        tok = None
        for operation, make_body, mode in self._AUTH_ATTEMPTS:
            body = make_body(self.username, self.password)
            name = f"POST /api/v2/{operation}  {{ {', '.join(body.keys())} }}"
            try:
                resp, hdrs = self._post(operation, body)

                if mode == "token":
                    tok = (resp.get("accessToken") or resp.get("access_token")
                           or resp.get("token")) if isinstance(resp, dict) else None
                    if tok:
                        self.token = tok
                        step(name, True, f"accessToken: {tok[:20]}…")
                        break
                    else:
                        keys = list(resp.keys()) if isinstance(resp, dict) else type(resp).__name__
                        step(name, False, f"HTTP 200, токена нет. Ключи: {keys}")

                elif mode == "cookie":
                    cookie_hdr = (hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or "")
                    if cookie_hdr:
                        # PT NGFW возвращает куку вида:
                        #   Authorization=eyJhbGci....; Path=/; HttpOnly; Secure
                        # Извлекаем значение: берём первую часть name=value
                        name_val = cookie_hdr.split(";")[0].strip()   # "Authorization=eyJ..."
                        if "=" in name_val:
                            cookie_name, cookie_val = name_val.split("=", 1)
                            # Если кука называется Authorization — это Bearer token
                            if cookie_name.strip().lower() in ("authorization", "token", "access_token"):
                                tok = cookie_val.strip()
                                self.token = tok
                                self._session_cookie = None  # не нужна кука — используем Bearer
                            else:
                                # Иная кука — передаём как Cookie-заголовок
                                tok = f"session:{cookie_val[:20]}"
                                self.token = tok
                                self._session_cookie = name_val
                        step(name, True, f"Set-Cookie [{cookie_name.strip()}]: {cookie_val[:30]}…")
                        break
                    else:
                        step(name, False, f"HTTP 200, Set-Cookie отсутствует. "
                             f"Заголовки ответа: {list(hdrs.keys())}")

            except (RuntimeError, ConnectionError) as e:
                step(name, False, str(e))

        if not tok:
            return result
        result["auth"]         = True
        result["token_prefix"] = tok[:20] + "…"

        # Последний шаг: проверяем API
        try:
            _, __ = self._post("GetDeviceGroupsTree", {})
            step("POST /api/v2/GetDeviceGroupsTree", True, "API доступен")
            result["api_reached"] = True
        except Exception as e:
            step("POST /api/v2/GetDeviceGroupsTree", False, str(e))
            return result

        # Загружаем список групп устройств для удобства
        try:
            groups = self.get_device_groups()
            result["device_groups"] = groups
            step("Список групп устройств", True, f"найдено: {len(groups)}")
        except Exception as e:
            step("Список групп устройств", False, str(e))
            result["device_groups"] = []

        return result

    # ─── Устройства ───────────────────────────────────────────────────────────

    def get_device_groups(self) -> list[dict]:
        try:
            resp, _ = self._post("GetDeviceGroupsTree", {})
            return self._flatten_group_tree(resp.get("groups") or [], "")
        except Exception as e:
            log.warning("GetDeviceGroupsTree: %s, trying ListDeviceGroups", e)
        try:
            resp, _ = self._post("ListDeviceGroups", {"limit": PAGE_SIZE})
            return self._flatten_group_tree(resp.get("groups") or [], "")
        except Exception as e:
            log.warning("ListDeviceGroups: %s", e)
            return []

    def _flatten_group_tree(self, nodes: list, path: str, depth: int = 0) -> list[dict]:
        result = []
        for node in nodes:
            name      = node.get("name") or node.get("id", "?")
            full_path = f"{path} / {name}" if path else name
            flat      = dict(node)
            flat["_path"]  = full_path
            flat["_depth"] = depth
            subgroups = flat.pop("subgroups", None) or []
            result.append(flat)
            result.extend(self._flatten_group_tree(subgroups, full_path, depth + 1))
        return result

    def get_virtual_contexts(self) -> list[dict]:
        try:
            resp, _ = self._post("ListVirtualContexts", {"limit": PAGE_SIZE})
            return resp.get("virtualContexts") or []
        except Exception as e:
            log.warning("ListVirtualContexts: %s", e)
            return []

    # ─── Правила ─────────────────────────────────────────────────────────────

    def get_rules(self, device_group_id: str) -> list[dict]:
        all_rules: list[dict] = []
        for precedence in ("RULE_PRECEDENCE_PRE", None, "RULE_PRECEDENCE_POST"):
            rules = self._list_rules_paged(device_group_id, precedence)
            for r in rules:
                r["_precedence"] = precedence or "default"
            all_rules.extend(rules)
            log.info("precedence=%-30s → %d rules", precedence or "default", len(rules))
        all_rules.sort(key=lambda r: r.get("globalPosition", r.get("position", 0)))
        return all_rules

    def _list_rules_paged(self, device_group_id: str, precedence: Optional[str]) -> list[dict]:
        items:  list[dict]    = []
        cursor: Optional[str] = None
        while True:
            body: dict = {"limit": PAGE_SIZE, "deviceGroupId": device_group_id}
            if precedence:
                body["precedence"] = precedence
            if cursor:
                body["cursor"] = cursor
            resp, _ = self._post("ListSecurityRules2", body)
            page   = resp.get("items") or []
            items.extend(page)
            cursor = resp.get("nextCursor")
            if not cursor or not page:
                break
        return items

    # ─── Сетевые объекты ─────────────────────────────────────────────────────

    def get_all_network_objects(self, device_group_id: str) -> dict[str, dict]:
        obj_map: dict[str, dict] = {}
        offset = 0
        while True:
            resp, _ = self._post("ListNetworkObjects", {
                "limit": PAGE_SIZE, "offset": offset,
                "deviceGroupId": device_group_id,
            })
            count = 0
            for key in ("addresses", "ranges", "fqdnAddresses", "geoAddresses", "networkGroups"):
                for obj in resp.get(key) or []:
                    oid = obj.get("id")
                    if oid:
                        obj_map[oid] = obj
                        count += 1
            if count < PAGE_SIZE:
                break
            offset += PAGE_SIZE
        log.info("Сетевых объектов: %d", len(obj_map))
        return obj_map

    def get_network_group_items(self, group_id: str) -> list[dict]:
        if group_id in self._net_group_cache:
            return self._net_group_cache[group_id]
        resp, _ = self._post("GetNetworkObjectGroup", {"id": group_id})
        items = (resp.get("group") or {}).get("items") or []
        self._net_group_cache[group_id] = items
        return items

    # ─── Сервисные объекты ────────────────────────────────────────────────────

    def get_all_service_objects(self, device_group_id: str) -> dict[str, dict]:
        obj_map: dict[str, dict] = {}
        offset = 0
        while True:
            resp, _ = self._post("ListServices", {
                "limit": PAGE_SIZE, "offset": offset,
                "deviceGroupId": device_group_id,
            })
            count = 0
            for obj in resp.get("services") or []:
                oid = obj.get("id")
                if oid:
                    obj["_kind"] = "service"
                    obj_map[oid] = obj
                    count += 1
            for obj in resp.get("serviceGroups") or []:
                oid = obj.get("id")
                if oid:
                    obj["_kind"] = "service_group"
                    obj_map[oid] = obj
                    count += 1
            if count < PAGE_SIZE:
                break
            offset += PAGE_SIZE
        log.info("Сервисных объектов: %d", len(obj_map))
        return obj_map

    def get_service_group_items(self, group_id: str) -> list[dict]:
        if group_id in self._svc_group_cache:
            return self._svc_group_cache[group_id]
        resp, _ = self._post("GetServiceGroup", {"id": group_id})
        items = (resp.get("serviceGroup") or {}).get("items") or []
        self._svc_group_cache[group_id] = items
        return items

    # ─── Статистика срабатываний ─────────────────────────────────────────────

    def get_rule_hits(self, rule_ids: list[str], batch_size: int = 30) -> list[dict]:
        """
        Запрашивает hits-счётчики для списка правил батчами.
        POST /api/v2/ListMetricsRulesStats { ruleIds: [...] }
        → { rules: [{ ruleId, hits, bytesRx, bytesTx }] }
        """
        results: list[dict] = []
        for i in range(0, len(rule_ids), batch_size):
            batch = rule_ids[i:i + batch_size]
            try:
                resp, _ = self._post("ListMetricsRulesStats", {"ruleIds": batch})
                results.extend(resp.get("rules") or [])
            except Exception as e:
                log.warning("ListMetricsRulesStats batch %d-%d: %s", i, i + len(batch), e)
        return results