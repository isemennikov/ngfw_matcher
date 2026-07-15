"""
ngfw-matcher — CLI для симуляции трафика через политию PT NGFW.

Два источника данных (выбираются флагом --source):
    ngfw    [приоритет] — прямой PT NGFW API (актуальные данные)
    backend             — REST API ngfw-manager (кэш PostgreSQL)

Три режима ввода трафика:
    одиночный запрос    — флаги --src --dst --dport --proto
    batch               — --batch traffic.csv
    интерактивный       — --interactive
"""
# Developed by Ilya Semennikov
from __future__ import annotations

import argparse
import getpass
import logging
import sys

from .output import die, print_version_footer
from .builder import _normalize_rule  # re-exported: used by web/state.py and web/routers/devices.py
from .commands import run, cmd_test_connection, cmd_find_rule, cmd_check_shadowed, cmd_rule_hits, cmd_fullview, cmd_nat_audit


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ngfw-matcher",
        description="Симулятор трафика для PT NGFW — находит совпадающее правило и выявляет дубли.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--host",   metavar="URL",
                   help="Адрес СУ: https://10.1.31.100  или  https://localhost:3223")
    p.add_argument("--user",   metavar="LOGIN", help="Логин")
    p.add_argument("--pass",   dest="password", metavar="PWD", help="Пароль")
    p.add_argument("--token",  metavar="TOKEN", help="Bearer-токен (вместо логина/пароля)")
    p.add_argument("--verify-ssl", action="store_true",
                   help="Проверять TLS-сертификат (по умолчанию отключено)")
    p.add_argument("--log-level", default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    sub = p.add_subparsers(dest="command", metavar="КОМАНДА")

    sub.add_parser("test-connection", help="Проверить подключение и авторизацию")

    # ── match ──────────────────────────────────────────────────────────────────
    m = sub.add_parser("match", help="Проверить трафик по правилам")
    m.add_argument("--source", choices=["ngfw", "backend"], default="ngfw",
                   help="ngfw (прямой API) | backend (кэш ngfw-manager). По умолчанию: ngfw")
    m.add_argument("--backend-host", metavar="URL",
                   help="URL ngfw-manager (при --source backend)")
    m.add_argument("--device", metavar="DEVICE_GROUP_ID",
                   help="deviceGroupId (если не указан — интерактивный выбор)")
    m.add_argument("--src",   metavar="IP/CIDR[,IP/CIDR...]",
                   help="Source IP/сеть или 'any'. Несколько через запятую.")
    m.add_argument("--dst",   metavar="IP/CIDR[,IP/CIDR...]",
                   help="Destination IP/сеть или 'any'. Несколько через запятую.")
    m.add_argument("--dport", metavar="PORTS",
                   help="Порт(ы): одиночный 443, диапазон 5000-5322, список 80,443,8080, any")
    m.add_argument("--proto", metavar="PROTO", help="tcp | udp | icmp | any")
    m.add_argument("--fullview", action="store_true",
                   help="Развернуть группы в выводе. С --output FILE.json — сохраняет JSON-скан.")
    m.add_argument("--overlap", action="store_true",
                   help="Нестрогий матчинг: включает правила с подсетями запроса.")
    m.add_argument("--interactive", "-i", action="store_true",
                   help="Интерактивный ввод трафика в цикле")
    m.add_argument("--batch",   metavar="FILE.csv", help="CSV с потоками трафика")
    m.add_argument("--output",  metavar="FILE.csv", help="Сохранить результаты в CSV")
    m.add_argument("--verbose", "-v", action="store_true")
    m.add_argument("--save-rules",   metavar="FILE.json", help="Сохранить правила в JSON")
    m.add_argument("--save-objects", metavar="FILE.json", help="Сохранить объекты в JSON")
    m.add_argument("--snapshot",     metavar="FILE.json", help="Снапшот ngfw-matcher (офлайн)")
    m.add_argument("--rules-file",   metavar="FILE.json", help="Правила из локального JSON")
    m.add_argument("--objects-file", metavar="FILE.json", help="Объекты из локального JSON")

    # ── find-rule ──────────────────────────────────────────────────────────────
    fr = sub.add_parser("find-rule", help="Найти правило по имени или UUID")
    fr.add_argument("name", metavar="PATTERN_OR_UUID",
                    help="Имя (подстрока, регистронезависимо) или UUID правила")
    fr.add_argument("--source", choices=["ngfw", "backend"], default="ngfw")
    fr.add_argument("--backend-host", metavar="URL")
    fr.add_argument("--device", metavar="DEVICE_GROUP_ID")
    fr.add_argument("--snapshot",     metavar="FILE.json", help="Снапшот ngfw-matcher (офлайн)")
    fr.add_argument("--rules-file",   metavar="FILE.json")
    fr.add_argument("--objects-file", metavar="FILE.json")
    fr.add_argument("--output", metavar="FILE.json", help="Экспорт найденных правил в JSON")

    # ── check-shadowed ─────────────────────────────────────────────────────────
    cs = sub.add_parser("check-shadowed", help="Найти теневые (перекрытые) правила")
    cs.add_argument("--source", choices=["ngfw", "backend"], default="ngfw")
    cs.add_argument("--backend-host", metavar="URL")
    cs.add_argument("--device", metavar="DEVICE_GROUP_ID")
    cs.add_argument("--snapshot",     metavar="FILE.json", help="Снапшот ngfw-matcher (офлайн)")
    cs.add_argument("--rules-file",   metavar="FILE.json")
    cs.add_argument("--objects-file", metavar="FILE.json")
    cs.add_argument("--output", metavar="FILE.json", help="Экспорт результатов в JSON")
    cs.add_argument("--partial", action="store_true",
                    help="Режим частичного пересечения")

    # ── rule-hits ──────────────────────────────────────────────────────────────
    rh = sub.add_parser("rule-hits",
                        help="Счётчики срабатываний правил (hits) с цветной шкалой")
    rh.add_argument("--device", metavar="DEVICE_GROUP_ID",
                    help="deviceGroupId (если не указан — интерактивный выбор)")
    rh.add_argument("--rule", metavar="PATTERN",
                    help="Фильтр по имени (подстрока). Если не указан — все правила.")
    rh.add_argument("--batch-size", type=int, default=30, metavar="N",
                    help="Размер батча для ListMetricsRulesStats (по умолчанию: 30)")
    rh.add_argument("--sort-hits", action="store_true",
                    help="Сортировать по убыванию hits")

    # ── fullview ───────────────────────────────────────────────────────────────
    fv = sub.add_parser("fullview",
                        help="Найти все правила где IP фигурирует в source или destination")
    fv.add_argument("--src", metavar="IP/CIDR[,...]",
                    help="Искать в sourceAddr. Несколько через запятую.")
    fv.add_argument("--dst", metavar="IP/CIDR[,...]",
                    help="Искать в destinationAddr. Несколько через запятую.")
    fv.add_argument("--dport", metavar="PORTS",
                    help="Фильтр по порту: 443, 80-90, 80,443, any. По умолчанию: any")
    fv.add_argument("--proto", metavar="PROTO", default="any",
                    help="tcp | udp | icmp | any (по умолчанию: any)")
    fv.add_argument("--overlap", action="store_true",
                    help="Включать правила с подсетями (overlap-режим)")
    fv.add_argument("--output", metavar="FILE.json",
                    help="Сохранить результаты в JSON с раскрытыми объектами")
    fv.add_argument("--source", choices=["ngfw", "backend"], default="ngfw")
    fv.add_argument("--backend-host", metavar="URL")
    fv.add_argument("--device", metavar="DEVICE_GROUP_ID")
    fv.add_argument("--snapshot", metavar="FILE.json", help="Снапшот ngfw-matcher (офлайн)")

    # ── nat-audit ──────────────────────────────────────────────────────────────
    na = sub.add_parser("nat-audit",
                        help="Показать NAT правила: тип (SNAT/DNAT), направление, адреса трансляции")
    na.add_argument("--source", choices=["ngfw", "backend"], default="ngfw")
    na.add_argument("--backend-host", metavar="URL")
    na.add_argument("--device", metavar="DEVICE_GROUP_ID")
    na.add_argument("--snapshot", metavar="FILE.json", help="Снапшот ngfw-matcher (офлайн)")
    na.add_argument("--type", dest="nat_type", choices=["snat", "dnat", "all"], default="all",
                    help="Фильтр по типу: snat | dnat | all (по умолчанию: all)")
    na.add_argument("--json", metavar="FILE|-",
                    help="Экспорт результатов с ассоциацией в JSON (- для stdout)")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(name)s: %(message)s",
    )

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if not args.token and args.user and not args.password:
        args.password = getpass.getpass(f"Пароль для {args.user}: ")

    try:
        if args.command == "test-connection":
            cmd_test_connection(args)
        elif args.command == "match":
            run(args)
        elif args.command == "find-rule":
            cmd_find_rule(args)
        elif args.command == "check-shadowed":
            cmd_check_shadowed(args)
        elif args.command == "rule-hits":
            cmd_rule_hits(args)
        elif args.command == "fullview":
            cmd_fullview(args)
        elif args.command == "nat-audit":
            cmd_nat_audit(args)
        print_version_footer()
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        die(str(e))


if __name__ == "__main__":
    main()
