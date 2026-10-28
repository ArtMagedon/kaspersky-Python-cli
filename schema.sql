PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id),
    name TEXT NOT NULL,
    UNIQUE(vendor_id, name)
);

CREATE TABLE IF NOT EXISTS product_versions (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    version TEXT NOT NULL,
    UNIQUE(product_id, version)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    vuln_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    publish_date TEXT NOT NULL DEFAULT '',
    start_vuln_version TEXT NOT NULL DEFAULT '0',
    fixed_version TEXT NOT NULL DEFAULT '',
    UNIQUE(product_id, vuln_id, fixed_version, description)
);

CREATE TABLE IF NOT EXISTS feed_versions_raw (
    id INTEGER PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    source_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_vulnerabilities_raw (
    id INTEGER PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    description TEXT NOT NULL,
    publish_date TEXT NOT NULL,
    start_vuln_version TEXT NOT NULL,
    fixed_version TEXT NOT NULL,
    source_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
CREATE INDEX IF NOT EXISTS idx_product_versions_product ON product_versions(product_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_product ON vulnerabilities(product_id);
