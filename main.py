#!/usr/bin/env python3
"""Консольный поиск безопасных версий и уязвимостей по локальной SQLite БД."""
import argparse
import re
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("vulnerabilities.db")


def version_key(value: str) -> tuple[int, ...]:
    """Преобразует числовую версию в кортеж для сравнения."""
    parts = re.findall(r"\d+", value or "")
    return tuple(int(part) for part in parts) if parts else (0,)


def compare_versions(left: str, right: str) -> int:
    a, b = version_key(left), version_key(right)
    size = max(len(a), len(b))
    a += (0,) * (size - len(a))
    b += (0,) * (size - len(b))
    return (a > b) - (a < b)


def is_vulnerable(version: str, vulnerability: dict) -> bool:
    """Эвристика для структуры предоставленного фида."""
    fixed = vulnerability["fixed_version"]
    start = str(vulnerability["start_vuln_version"])
    if not fixed:
        return False
    if start != "0":
        if version_key(version)[0] != version_key(start)[0]:
            return False
    return compare_versions(version, fixed) < 0


def connect():
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"База {DB_PATH} не найдена. Сначала выполните: python main.py --init"
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def find_products(conn, name):
    return conn.execute(
        """SELECT p.id, v.name AS vendor, p.name AS product
           FROM products p JOIN vendors v ON v.id = p.vendor_id
           WHERE p.name = ? COLLATE NOCASE
           ORDER BY v.name""",
        (name.strip(),),
    ).fetchall()


def list_products(conn):
    rows = conn.execute(
        """SELECT v.name AS vendor, p.name AS product
           FROM products p JOIN vendors v ON v.id = p.vendor_id
           ORDER BY p.name COLLATE NOCASE"""
    ).fetchall()
    for row in rows:
        print(f"{row['product']} — {row['vendor']}")


def get_versions(conn, product_id):
    return [r["version"] for r in conn.execute(
        "SELECT version FROM product_versions WHERE product_id = ?",
        (product_id,),
    )]


def get_vulnerabilities(conn, product_id):
    rows = conn.execute(
        """SELECT vuln_id, description, publish_date, start_vuln_version, fixed_version
           FROM vulnerabilities WHERE product_id = ?
           ORDER BY publish_date DESC, vuln_id""",
        (product_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def command_safe(conn, product_name):
    products = find_products(conn, product_name)
    if not products:
        print(f"Продукт не найден: {product_name}")
        return 1
    for product in products:
        versions = get_versions(conn, product["id"])
        if not versions:
            print(f"{product['product']}: в фиде нет версий.")
            continue
        vulns = get_vulnerabilities(conn, product["id"])
        safe = [
            version for version in versions
            if not any(is_vulnerable(version, vuln) for vuln in vulns)
        ]
        if not safe:
            print(f"{product['product']}: среди версий фида безопасная версия не найдена.")
        else:
            best = max(safe, key=version_key)
            print(f"{product['product']}: {best}")
    return 0


def command_vulnerabilities(conn, product_name, version):
    products = find_products(conn, product_name)
    if not products:
        print(f"Продукт не найден: {product_name}")
        return 1
    for product in products:
        known_versions = get_versions(conn, product["id"])
        if known_versions and version not in known_versions:
            print(f"Предупреждение: версия {version} отсутствует в фиде версий.")
        vulns = get_vulnerabilities(conn, product["id"])
        matches = [v for v in vulns if is_vulnerable(version, v)]
        print(f"{product['product']} {version}:")
        if not matches:
            print("  По данным загруженных фидов подходящие уязвимости не найдены.")
        else:
            for vuln in matches:
                print(f"  {vuln['vuln_id']} — {vuln['description']}")
                print(f"    Дата публикации: {vuln['publish_date']}")
                print(f"    Исправлено в версии: {vuln['fixed_version']}")
    return 0


def initialize_database():
    import json

    folder = Path(__file__).resolve().parent
    versions_path = folder / "versions.json"
    vulnerabilities_path = folder / "vulnerabilities.json"
    if not versions_path.exists() or not vulnerabilities_path.exists():
        raise FileNotFoundError(
            "Для инициализации положите versions.json и vulnerabilities.json рядом с main.py."
        )
    versions = json.loads(versions_path.read_text(encoding="utf-8"))
    vulnerabilities = json.loads(vulnerabilities_path.read_text(encoding="utf-8"))
    db_path = folder / "vulnerabilities.db"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript("""
        PRAGMA foreign_keys = ON;
        CREATE TABLE feed_versions_raw (
            id INTEGER PRIMARY KEY, vendor TEXT NOT NULL, product TEXT NOT NULL,
            version TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE feed_vulnerabilities_raw (
            id INTEGER PRIMARY KEY, vendor TEXT NOT NULL, product TEXT NOT NULL,
            vuln_id TEXT NOT NULL, description TEXT NOT NULL, publish_date TEXT NOT NULL,
            start_vuln_version TEXT NOT NULL, fixed_version TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE vendors (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE products (
            id INTEGER PRIMARY KEY, vendor_id INTEGER NOT NULL REFERENCES vendors(id),
            name TEXT NOT NULL, UNIQUE(vendor_id, name)
        );
        CREATE TABLE product_versions (
            id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            version TEXT NOT NULL, UNIQUE(product_id, version)
        );
        CREATE TABLE vulnerabilities (
            id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            vuln_id TEXT NOT NULL, description TEXT NOT NULL, publish_date TEXT NOT NULL,
            start_vuln_version TEXT NOT NULL, fixed_version TEXT NOT NULL,
            UNIQUE(product_id, vuln_id, fixed_version, description)
        );
        CREATE INDEX idx_products_name ON products(name COLLATE NOCASE);
        CREATE INDEX idx_versions_product ON product_versions(product_id);
        CREATE INDEX idx_vulns_product ON vulnerabilities(product_id);
        """)
        for row in versions:
            conn.execute(
                "INSERT INTO feed_versions_raw (vendor, product, version, raw_json) VALUES (?, ?, ?, ?)",
                (str(row["vendor"]), str(row["product"]), str(row["version"]),
                 json.dumps(row, ensure_ascii=False, sort_keys=True)),
            )
        for row in vulnerabilities:
            conn.execute(
                """INSERT INTO feed_vulnerabilities_raw
                   (vendor, product, vuln_id, description, publish_date,
                    start_vuln_version, fixed_version, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(row["vendor"]), str(row["product"]), str(row["KLA_id"]),
                 str(row["description"]), str(row["publish_date"]),
                 str(row["start_vuln_version"]), str(row["fixed_version"]),
                 json.dumps(row, ensure_ascii=False, sort_keys=True)),
            )

        vendor_ids, product_ids = {}, {}

        def get_product_id(vendor, product):
            vendor_key, product_key = vendor.strip(), product.strip()
            if vendor_key not in vendor_ids:
                conn.execute("INSERT OR IGNORE INTO vendors(name) VALUES (?)", (vendor_key,))
                vendor_ids[vendor_key] = conn.execute(
                    "SELECT id FROM vendors WHERE name = ?", (vendor_key,)
                ).fetchone()[0]
            key = (vendor_key, product_key)
            if key not in product_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO products(vendor_id, name) VALUES (?, ?)",
                    (vendor_ids[vendor_key], product_key),
                )
                product_ids[key] = conn.execute(
                    "SELECT id FROM products WHERE vendor_id = ? AND name = ?",
                    (vendor_ids[vendor_key], product_key),
                ).fetchone()[0]
            return product_ids[key]

        for row in versions:
            pid = get_product_id(row["vendor"], row["product"])
            conn.execute(
                "INSERT OR IGNORE INTO product_versions(product_id, version) VALUES (?, ?)",
                (pid, str(row["version"])),
            )

        def normalize_product(name):
            return re.sub(r"\s*\(MSI installer\)\s*", "", name, flags=re.I).strip().casefold()

        normalized_ids = {
            (vendor.casefold(), normalize_product(product)): pid
            for (vendor, product), pid in product_ids.items()
        }
        for row in vulnerabilities:
            key = (row["vendor"].strip().casefold(), normalize_product(row["product"]))
            pid = normalized_ids.get(key)
            if pid is None:
                pid = get_product_id(row["vendor"], row["product"])
            conn.execute(
                """INSERT OR IGNORE INTO vulnerabilities
                   (product_id, vuln_id, description, publish_date, start_vuln_version, fixed_version)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (pid, row["KLA_id"], row["description"], row["publish_date"],
                 str(row["start_vuln_version"]), str(row["fixed_version"])),
            )
        conn.commit()
        print(f"База создана: {db_path}")
        print(f"Строк в исходном фиде версий: {conn.execute('SELECT COUNT(*) FROM feed_versions_raw').fetchone()[0]}")
        print(f"Уникальных версий в рабочей таблице: {conn.execute('SELECT COUNT(*) FROM product_versions').fetchone()[0]}")
        print(f"Строк в исходном фиде уязвимостей: {conn.execute('SELECT COUNT(*) FROM feed_vulnerabilities_raw').fetchone()[0]}")
        print(f"Уникальных записей уязвимостей в рабочей таблице: {conn.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]}")
        print(f"Продуктов: {conn.execute('SELECT COUNT(*) FROM products').fetchone()[0]}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Поиск безопасных версий и уязвимостей в локальной базе."
    )
    parser.add_argument("--init", action="store_true", help="создать/пересоздать БД из JSON-фидов")
    parser.add_argument("--list", action="store_true", help="вывести список продуктов")
    subparsers = parser.add_subparsers(dest="command")
    safe_parser = subparsers.add_parser("safe", help="найти наибольшую версию без известных уязвимостей")
    safe_parser.add_argument("product", help="точное название продукта")
    vuln_parser = subparsers.add_parser("vulns", help="показать уязвимости продукта в указанной версии")
    vuln_parser.add_argument("product", help="точное название продукта")
    vuln_parser.add_argument("version", help="версия продукта")
    args = parser.parse_args()

    if args.init:
        initialize_database()
        return
    try:
        with connect() as conn:
            if args.list:
                list_products(conn)
            elif args.command == "safe":
                raise SystemExit(command_safe(conn, args.product))
            elif args.command == "vulns":
                raise SystemExit(command_vulnerabilities(conn, args.product, args.version))
            else:
                parser.print_help()
    except (sqlite3.Error, FileNotFoundError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
