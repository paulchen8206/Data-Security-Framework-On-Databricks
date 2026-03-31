"""General Encrypting Demo — Unity Catalog Encryption Script

Showcases the five building blocks for general column-level encryption
with Unity Catalog:

  1. Fine-grained access control  — KEK lives in a privileged catalog/schema
                                    inaccessible to regular users.
  2. AES functions                — encrypt() / decrypt() mediate all crypto
                                    ops; users never touch the KEK directly.
  3. Secrets for DEK material     — encrypted DEK, IV, and AAD stored in
                                    Databricks secret scope; ciphertext only
                                    is ever exposed.
  4. Column unmasks               — salary column is stored as ciphertext at
                                    rest; a column mask (definer-rights) auto-
                                    decrypts it for authorised users; a row
                                    filter limits each manager to their own
                                    employees.
  5. Key rotation                 — new KEK generated, DEK re-wrapped, secrets
                                    updated; the payroll table is never
                                    rewritten.
"""

import argparse
import importlib
import random
import string
from base64 import b64encode
from dataclasses import dataclass
from os import urandom
from pathlib import Path
from shutil import copy2

from pyspark.sql import SparkSession


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DemoConfig:
    secret_scope: str
    kek_name: str
    keyvault_user: str
    data_catalog: str
    data_schema: str
    data_volume: str
    key_catalog: str
    key_schema: str


@dataclass
class DekMaterial:
    """Plaintext DEK material — kept in memory only, never persisted."""
    dek: str
    iv: str
    aad: str


def parse_args() -> DemoConfig:
    parser = argparse.ArgumentParser(
        description="Envelope Encryption with Unity Catalog demo."
    )
    parser.add_argument("--secret-scope", default="piiscope", dest="secret_scope")
    parser.add_argument("--kek-name", default="piikeyname", dest="kek_name")
    parser.add_argument("--keyvault-user", default="payroll_managers", dest="keyvault_user")
    parser.add_argument("--data-catalog", default="consume", dest="data_catalog")
    parser.add_argument("--data-schema", default="catalog", dest="data_schema")
    parser.add_argument("--data-volume", default="synthetic_data", dest="data_volume")
    parser.add_argument("--key-catalog", default="sys", dest="key_catalog")
    parser.add_argument("--key-schema", default="crypto", dest="key_schema")
    return DemoConfig(**vars(parser.parse_args()))


# ── SQL helpers ────────────────────────────────────────────────────────────────

def quote_identifier(identifier: str) -> str:
    return f"`{identifier.replace('`', '``')}`"


def qualified_identifier(*parts: str) -> str:
    return ".".join(quote_identifier(part) for part in parts)


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def show_query(spark: SparkSession, label: str, query: str) -> None:
    print(f"\n  [{label}]")
    spark.sql(query).show(truncate=False)


def query_scalar(spark: SparkSession, query: str) -> str:
    row = spark.sql(query).first()
    if row is None:
        raise RuntimeError(f"Expected one row but got none from: {query}")
    return row[0]


# ── Step 1: Data staging ──────────────────────────────────────────────────────

def resolve_sample_data_dir() -> Path:
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir.parent / "sample_data",
        Path.cwd() / "code" / "sample_data",
        Path.cwd() / "sample_data",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not locate sample data. Checked: " + ", ".join(str(p) for p in candidates)
    )


def stage_data(config: DemoConfig, spark: SparkSession) -> None:
    """Copy bundled CSV files into a Unity Catalog volume for ingestion."""
    print("\n=== Step 1: Staging sample data ===")
    data_ns = qualified_identifier(config.data_catalog, config.data_schema)
    spark.sql(f"CREATE CATALOG IF NOT EXISTS {quote_identifier(config.data_catalog)}")
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {data_ns}")
    spark.sql(
        f"CREATE VOLUME IF NOT EXISTS "
        f"{qualified_identifier(config.data_catalog, config.data_schema, config.data_volume)}"
    )

    src = resolve_sample_data_dir()
    dst = Path(f"/Volumes/{config.data_catalog}/{config.data_schema}/{config.data_volume}")
    dst.mkdir(parents=True, exist_ok=True)
    for csv_file in src.glob("*.csv"):
        copy2(csv_file, dst / csv_file.name)
        print(f"  Staged {csv_file.name}")


# ── Step 2: Employee tables ───────────────────────────────────────────────────

def create_employee_tables(config: DemoConfig, spark: SparkSession) -> tuple[str, str]:
    """Load employee hierarchy and UPN tables from volume CSVs."""
    print("\n=== Step 2: Creating employee tables ===")
    hier_table = qualified_identifier(config.data_catalog, config.data_schema, "employee_hierarchy")
    upn_table = qualified_identifier(config.data_catalog, config.data_schema, "employee_upn")

    for table, filename in [
        (hier_table, "employee_hierarchy.csv"),
        (upn_table, "employee_upn.csv"),
    ]:
        path = (
            f"/Volumes/{config.data_catalog}/{config.data_schema}"
            f"/{config.data_volume}/{filename}"
        )
        spark.sql(
            f"""
CREATE OR REPLACE TABLE {table} AS
SELECT * FROM read_files(
    {sql_string(path)},
    format => 'csv',
    header => true,
    inferSchema => true)
"""
        )

    show_query(spark, "employee_hierarchy", f"SELECT * FROM {hier_table}")
    show_query(spark, "employee_upn", f"SELECT * FROM {upn_table}")
    return hier_table, upn_table


# ── Step 3: Key vault & KEK (Building block 1) ────────────────────────────────

def setup_key_vault(config: DemoConfig, spark: SparkSession) -> tuple[str, str]:
    """
    Building block 1 — Fine-grained access control.

    The KEK is stored in key_catalog.key_schema — a privileged catalog/schema
    accessible only to admins.  Unity Catalog's inheritance model ensures
    that regular users cannot query key_vault directly.
    """
    print("\n=== Step 3: Setting up key vault in privileged catalog ===")
    key_ns = qualified_identifier(config.key_catalog, config.key_schema)
    key_vault_table = qualified_identifier(config.key_catalog, config.key_schema, "key_vault")

    spark.sql(f"CREATE CATALOG IF NOT EXISTS {quote_identifier(config.key_catalog)}")
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {key_ns}")
    spark.sql(
        f"""
CREATE OR REPLACE TABLE {key_vault_table} (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY,
    created_date DATE,
    created_time TIMESTAMP,
    last_modified_time TIMESTAMP,
    created_by STRING,
    managed_by STRING,
    key_name STRING,
    key_version INT,
    key_enabled BOOLEAN,
    key_type STRING,
    key STRING)
"""
    )

    kek = b64encode(urandom(24)).decode("utf-8")
    spark.sql(
        f"""
INSERT INTO {key_vault_table}
    (created_date, created_time, last_modified_time, created_by, managed_by,
     key_name, key_version, key_enabled, key_type, key)
VALUES (
    current_date(), current_timestamp(), current_timestamp(),
    session_user(), session_user(),
    {sql_string(config.kek_name)}, 1, true, 'KEK', {sql_string(kek)})
"""
    )

    show_query(
        spark,
        "key_vault (admin view — regular users cannot access this table)",
        f"SELECT id, key_name, key_version, key_enabled, key_type FROM {key_vault_table}",
    )
    return kek, key_vault_table


# ── Step 4: AES crypto functions (Building block 2) ───────────────────────────

def create_crypto_functions(
    config: DemoConfig, spark: SparkSession, key_vault_table: str
) -> tuple[str, str, str]:
    """
    Building block 2 — AES functions in the privileged schema.

    unwrap_key() decrypts DEK material using the KEK from key_vault.
    encrypt()    wraps column values with the DEK obtained via unwrap_key.
    decrypt()    unwraps and decrypts — this function will be registered as
                 a column mask: it runs with definer's rights so end users
                 never directly touch key_vault or the KEK.
    """
    print("\n=== Step 4: Creating AES crypto functions ===")
    unwrap_key_fn = qualified_identifier(config.key_catalog, config.key_schema, "unwrap_key")
    encrypt_fn = qualified_identifier(config.key_catalog, config.key_schema, "encrypt")
    decrypt_fn = qualified_identifier(config.key_catalog, config.key_schema, "decrypt")

    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {unwrap_key_fn}(key_to_unwrap STRING, key_to_use STRING)
RETURNS STRING
RETURN aes_decrypt(
    unbase64(key_to_unwrap),
    (SELECT key FROM {key_vault_table}
     WHERE key_enabled AND key_name = key_to_use
     ORDER BY created_date DESC LIMIT 1),
    'GCM',
    'DEFAULT')
"""
    )

    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {encrypt_fn}(col STRING)
RETURNS STRING
RETURN base64(aes_encrypt(
    col,
    {unwrap_key_fn}(secret({sql_string(config.secret_scope)}, 'dek'), {sql_string(config.kek_name)}),
    'GCM',
    'DEFAULT',
    {unwrap_key_fn}(secret({sql_string(config.secret_scope)}, 'iv'),  {sql_string(config.kek_name)}),
    {unwrap_key_fn}(secret({sql_string(config.secret_scope)}, 'aad'), {sql_string(config.kek_name)})
))
"""
    )

    # decrypt() is used as a column mask — runs with definer's (admin) rights
    # so end users can decrypt transparently without accessing key_vault.
    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {decrypt_fn}(col STRING)
RETURNS STRING
RETURN nvl(
    CAST(try_aes_decrypt(
        unbase64(col),
        {unwrap_key_fn}(secret({sql_string(config.secret_scope)}, 'dek'), {sql_string(config.kek_name)}),
        'GCM',
        'DEFAULT',
        {unwrap_key_fn}(secret({sql_string(config.secret_scope)}, 'aad'), {sql_string(config.kek_name)})
    ) AS STRING),
    col)
"""
    )

    print(f"  Created: {unwrap_key_fn}")
    print(f"  Created: {encrypt_fn}")
    print(f"  Created: {decrypt_fn}  ← will be registered as column mask")
    return unwrap_key_fn, encrypt_fn, decrypt_fn


# ── Step 5: DEK generation & secret storage (Building block 3) ───────────────

def create_and_store_dek(
    config: DemoConfig, spark: SparkSession, kek: str
) -> DekMaterial:
    """
    Building block 3 — Secrets to store and access encrypted DEK material.

    The DEK, IV, and AAD are generated fresh, encrypted with the KEK, and
    stored in the Databricks secret scope.  Even if a user enumerates the
    secret, they only ever see the KEK-encrypted ciphertext — useless without
    access to the KEK in key_vault.
    """
    print("\n=== Step 5: Generating DEK and storing encrypted material in secrets ===")
    dek = b64encode(urandom(24)).decode("utf-8")
    iv = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
    aad = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    enc_dek = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(dek)},  {sql_string(kek)}, 'GCM', 'DEFAULT'))",
    )
    enc_iv = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(iv)},   {sql_string(kek)}, 'GCM', 'DEFAULT'))",
    )
    enc_aad = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(aad)},  {sql_string(kek)}, 'GCM', 'DEFAULT'))",
    )

    workspace_client = importlib.import_module("databricks.sdk").WorkspaceClient()
    try:
        workspace_client.secrets.create_scope(scope=config.secret_scope)
    except Exception as exc:
        print(f"  Secret scope already exists or note: {exc}")

    workspace_client.secrets.put_secret(scope=config.secret_scope, key="dek", string_value=enc_dek)
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="iv",  string_value=enc_iv)
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="aad", string_value=enc_aad)

    workspace_module = importlib.import_module("databricks.sdk.service.workspace")
    workspace_client.secrets.put_acl(
        scope=config.secret_scope,
        permission=workspace_module.AclPermission.READ,
        principal=config.keyvault_user,
    )

    print(f"  Encrypted DEK material stored in secret scope '{config.secret_scope}'")
    print(f"  READ access granted to '{config.keyvault_user}'")
    return DekMaterial(dek=dek, iv=iv, aad=aad)


# ── Step 6: Encrypted payroll table ──────────────────────────────────────────

def create_encrypted_payroll(
    config: DemoConfig,
    spark: SparkSession,
    hier_table: str,
    upn_table: str,
    encrypt_fn: str,
) -> str:
    """
    Join employee + manager data and store salary as ciphertext.
    The resulting table is the protected asset: store it anywhere and users
    see only encrypted salary values.
    """
    print("\n=== Step 6: Creating encrypted payroll table ===")
    payroll_table = qualified_identifier(config.data_catalog, config.data_schema, "payroll_data")

    spark.sql(
        f"""
CREATE OR REPLACE TABLE {payroll_table} AS
SELECT
    eh.employee_id,
    eh.first_name,
    eh.last_name,
    eu.manager_id,
    eu.manager_email,
    {encrypt_fn}(CAST(eh.salary AS STRING)) AS salary
FROM {hier_table} eh
LEFT JOIN {upn_table} eu ON eh.employee_id = eu.employee_id
"""
    )

    show_query(
        spark,
        "payroll_data — raw table (no mask): salary is ciphertext",
        f"SELECT * FROM {payroll_table} LIMIT 5",
    )
    return payroll_table


# ── Step 7: Column mask + row filter (Building block 4) ──────────────────────

def apply_column_mask_and_row_filter(
    config: DemoConfig,
    spark: SparkSession,
    payroll_table: str,
    decrypt_fn: str,
) -> None:
    """
    Building block 4 — Column unmasks protect data by default.

    Column mask (decrypt_fn):
      Applied directly to the payroll_data table's salary column.
      The function runs with the DEFINER's rights (admin), not the invoker's.
      This means Unity Catalog mediates access to the KEK on the user's behalf —
      they can decrypt transparently without any privilege on key_vault.

    Row filter (payroll_manager_filter):
      Ensures each user sees only the rows where manager_email = current_user().
      current_user() in a mask/filter returns the INVOKER's identity, giving
      per-user data scoping without a separate view.
    """
    print("\n=== Step 7: Applying column mask and row filter ===")

    row_filter_fn = qualified_identifier(
        config.data_catalog, config.data_schema, "payroll_manager_filter"
    )
    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {row_filter_fn}(manager_email STRING)
RETURNS BOOLEAN
RETURN manager_email = current_user()
"""
    )
    print(f"  Created row filter function: {row_filter_fn}")

    # Column mask: salary is auto-decrypted via definer-rights function
    spark.sql(f"ALTER TABLE {payroll_table} ALTER COLUMN salary SET MASK {decrypt_fn}")
    print(f"  Column mask applied on salary  → {decrypt_fn}")

    # Row filter: each manager sees only their own employees
    spark.sql(f"ALTER TABLE {payroll_table} SET ROW FILTER {row_filter_fn} ON (manager_email)")
    print(f"  Row filter applied on manager_email → {row_filter_fn}")

    show_query(
        spark,
        "payroll_data — with mask active (salary decrypted, rows filtered to current_user)",
        f"SELECT * FROM {payroll_table}",
    )


# ── Step 8: Key rotation (Building block 5) ───────────────────────────────────

def rotate_kek(
    config: DemoConfig,
    spark: SparkSession,
    dek_material: DekMaterial,
    key_vault_table: str,
    payroll_table: str,
) -> None:
    """
    Building block 5 — Rotate the KEK without rewriting payroll data.

    Process:
      a. Generate a new KEK (version 2, same key_name).
      b. Re-encrypt the in-memory DEK, IV, and AAD with the new KEK.
      c. Overwrite the three secrets with the freshly wrapped values.
      d. Disable the old KEK version in key_vault (key_enabled = false).
      e. Insert the new KEK into key_vault as version 2.

    The unwrap_key() function selects the latest enabled key by key_name, so
    it automatically switches to the new KEK.  The payroll_data table is
    untouched — the salary ciphertext (encrypted with the DEK) is unchanged;
    only the DEK's wrapper changed.
    """
    print("\n=== Step 8: Key rotation — new KEK, no data rewrite ===")
    print(f"  payroll_data row count (before): ", end="")
    print(query_scalar(spark, f"SELECT COUNT(*) FROM {payroll_table}"))

    new_kek = b64encode(urandom(24)).decode("utf-8")

    # Re-encrypt the same DEK material using the new KEK
    new_enc_dek = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(dek_material.dek)},  {sql_string(new_kek)}, 'GCM', 'DEFAULT'))",
    )
    new_enc_iv = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(dek_material.iv)},   {sql_string(new_kek)}, 'GCM', 'DEFAULT'))",
    )
    new_enc_aad = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(dek_material.aad)},  {sql_string(new_kek)}, 'GCM', 'DEFAULT'))",
    )

    # Overwrite secrets — old wrapped DEK material is replaced atomically
    workspace_client = importlib.import_module("databricks.sdk").WorkspaceClient()
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="dek", string_value=new_enc_dek)
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="iv",  string_value=new_enc_iv)
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="aad", string_value=new_enc_aad)
    print("  Secrets updated with new KEK-wrapped DEK material")

    # Disable old KEK version
    spark.sql(
        f"""
UPDATE {key_vault_table}
SET key_enabled = false, last_modified_time = current_timestamp()
WHERE key_name = {sql_string(config.kek_name)} AND key_version = 1
"""
    )

    # Insert new KEK version
    spark.sql(
        f"""
INSERT INTO {key_vault_table}
    (created_date, created_time, last_modified_time, created_by, managed_by,
     key_name, key_version, key_enabled, key_type, key)
VALUES (
    current_date(), current_timestamp(), current_timestamp(),
    session_user(), session_user(),
    {sql_string(config.kek_name)}, 2, true, 'KEK', {sql_string(new_kek)})
"""
    )
    print("  key_vault: v1 disabled, v2 inserted")

    show_query(
        spark,
        "key_vault after rotation",
        f"SELECT id, key_name, key_version, key_enabled, key_type FROM {key_vault_table}",
    )

    # Verify the column mask continues to decrypt correctly via the new KEK
    print("\n  Verifying column mask still decrypts correctly after rotation...")
    show_query(
        spark,
        "payroll_data after key rotation (salary still decrypts via new KEK, table unchanged)",
        f"SELECT * FROM {payroll_table}",
    )
    print("  Key rotation complete.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    config = parse_args()
    spark = SparkSession.builder.getOrCreate()

    # Steps 1–2: data preparation
    stage_data(config, spark)
    hier_table, upn_table = create_employee_tables(config, spark)

    # Step 3: privileged key vault — Building block 1 (fine-grained access control)
    kek, key_vault_table = setup_key_vault(config, spark)

    # Step 4: AES crypto functions — Building block 2
    _, encrypt_fn, decrypt_fn = create_crypto_functions(config, spark, key_vault_table)

    # Step 5: DEK material in secrets — Building block 3
    dek_material = create_and_store_dek(config, spark, kek)

    # Step 6: encrypted payroll table
    payroll_table = create_encrypted_payroll(
        config, spark, hier_table, upn_table, encrypt_fn
    )

    # Step 7: column mask + row filter — Building block 4 (column unmasks)
    apply_column_mask_and_row_filter(config, spark, payroll_table, decrypt_fn)

    # Step 8: key rotation without data rewrite — Building block 5
    rotate_kek(config, spark, dek_material, key_vault_table, payroll_table)


if __name__ == "__main__":
    main()
