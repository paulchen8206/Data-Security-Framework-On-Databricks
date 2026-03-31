"""Specific Encrypting Demo — Steps 0-8 walkthrough for column-level encryption with Unity Catalog.

This script demonstrates the end-to-end process for securing sensitive payroll data:

  Step 0    — Set up the data catalog, schema, and volume; stage source CSVs.
  Step 1    — Load employee hierarchy and manager-mapping tables.
  Steps 2-4 — Create a privileged key catalog/schema, insert the Key Encryption Key (KEK),
               and register AES helper functions (unwrap_key, encrypt).
  Step 5    — Generate the Data Encryption Key (DEK), IV, and AAD; encrypt each with the KEK
               and store the ciphertext in a Databricks secret scope.
  Steps 6-8 — Encrypt salary values into payroll_encrypted, create the decrypt() function,
               and build a manager-filtered decrypted view (payroll_decrypted) that uses
               current_user() to scope rows to the querying manager.
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
    """Immutable runtime configuration resolved from CLI arguments."""

    secret_scope: str
    kek_name: str
    keyvault_user: str
    data_catalog: str
    data_schema: str
    data_volume: str
    key_catalog: str
    key_schema: str


def parse_args() -> DemoConfig:
    """Parse CLI arguments and return a DemoConfig instance."""
    parser = argparse.ArgumentParser(
        description="Secure payroll data with Databricks encryption and row filtering.",
    )
    parser.add_argument("--secret-scope", default="piiscope", dest="secret_scope")
    parser.add_argument("--kek-name", default="piikeyname", dest="kek_name")
    parser.add_argument("--keyvault-user", default="payroll_managers", dest="keyvault_user")
    parser.add_argument("--data-catalog", default="consume", dest="data_catalog")
    parser.add_argument("--data-schema", default="catalog", dest="data_schema")
    parser.add_argument("--data-volume", default="synthetic_data", dest="data_volume")
    parser.add_argument("--key-catalog", default="sys", dest="key_catalog")
    parser.add_argument("--key-schema", default="crypto", dest="key_schema")
    args = parser.parse_args()
    return DemoConfig(**vars(args))


# ── SQL helpers ────────────────────────────────────────────────────────────────

def quote_identifier(identifier: str) -> str:
    """Wrap a Unity Catalog identifier in backticks, escaping any embedded backticks."""
    return f"`{identifier.replace('`', '``')}`"


def qualified_identifier(*parts: str) -> str:
    """Return a fully-qualified, backtick-quoted identifier (e.g. catalog.schema.table)."""
    return ".".join(quote_identifier(part) for part in parts)


def sql_string(value: str) -> str:
    """Return a SQL single-quoted string literal, escaping embedded single quotes."""
    return "'" + value.replace("'", "''") + "'"


def show_query(spark: SparkSession, query: str) -> None:
    """Execute a SELECT query and print all rows without truncation."""
    spark.sql(query).show(truncate=False)


def query_scalar(spark: SparkSession, query: str) -> str:
    """Execute a query expected to return exactly one row and return the first column value."""
    row = spark.sql(query).first()
    if row is None:
        raise RuntimeError(f"Expected one row from query but received none: {query}")
    return row[0]


# ── Step 0: Data staging ──────────────────────────────────────────────────────

def resolve_sample_data_dir() -> Path:
    """
    Locate the bundled sample-data directory.

    Checks three candidate locations in priority order:
      1. ../sample_data relative to the script (local dev / bundle layout).
      2. code/sample_data under the current working directory.
      3. sample_data under the current working directory.
    """
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir.parent / "sample_data",
        Path.cwd() / "code" / "sample_data",
        Path.cwd() / "sample_data",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched_paths = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"Could not locate bundled sample data. Checked: {searched_paths}")


def stage_sample_data(config: DemoConfig, spark: SparkSession) -> None:
    """
    Create the target Unity Catalog catalog, schema, and volume, then copy
    bundled CSV files into the volume so they can be ingested with read_files().
    """
    print("\n=== Step 0: Staging sample data ===")
    data_namespace = qualified_identifier(config.data_catalog, config.data_schema)
    spark.sql(f"CREATE CATALOG IF NOT EXISTS {quote_identifier(config.data_catalog)}")
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {data_namespace}")
    spark.sql(
        f"CREATE VOLUME IF NOT EXISTS {qualified_identifier(config.data_catalog, config.data_schema, config.data_volume)}"
    )

    # Copy CSVs from the local bundle into the Unity Catalog volume path
    source_data_dir = resolve_sample_data_dir()
    volume_data_dir = Path(f"/Volumes/{config.data_catalog}/{config.data_schema}/{config.data_volume}")
    volume_data_dir.mkdir(parents=True, exist_ok=True)

    for source_file in source_data_dir.glob("*.csv"):
        copy2(source_file, volume_data_dir / source_file.name)
        print(f"  Staged {source_file.name}")


# ── Step 1: Employee tables ───────────────────────────────────────────────────

def create_employee_tables(config: DemoConfig, spark: SparkSession) -> tuple[str, str]:
    """
    Load employee hierarchy (IDs, names, salary) and manager-UPN mapping tables
    from the staged volume CSVs.  Returns qualified table names for both tables.
    """
    print("\n=== Step 1: Creating employee tables ===")
    employee_hierarchy_table = qualified_identifier(config.data_catalog, config.data_schema, "employee_hierarchy")
    employee_upn_table = qualified_identifier(config.data_catalog, config.data_schema, "employee_upn")
    employee_hierarchy_path = (
        f"/Volumes/{config.data_catalog}/{config.data_schema}/{config.data_volume}/employee_hierarchy.csv"
    )
    employee_upn_path = (
        f"/Volumes/{config.data_catalog}/{config.data_schema}/{config.data_volume}/employee_upn.csv"
    )

    spark.sql(
        f"""
CREATE OR REPLACE TABLE {employee_hierarchy_table} AS
SELECT * FROM read_files(
    {sql_string(employee_hierarchy_path)},
    format => 'csv',
    header => true,
    inferSchema => true)
"""
    )
    show_query(spark, f"SELECT * FROM {employee_hierarchy_table}")

    spark.sql(
        f"""
CREATE OR REPLACE TABLE {employee_upn_table} AS
SELECT * FROM read_files(
    {sql_string(employee_upn_path)},
    format => 'csv',
    header => true,
    inferSchema => true)
"""
    )
    show_query(spark, f"SELECT * FROM {employee_upn_table}")

    return employee_hierarchy_table, employee_upn_table


# ── Steps 2–4: Key vault, KEK, and AES functions ──────────────────────────────

def create_key_vault(config: DemoConfig, spark: SparkSession) -> tuple[str, str, str, str]:
    """
    Set up the privileged key catalog/schema, store the Key Encryption Key (KEK),
    and create AES helper functions.

    Building block 1 — Fine-grained access control:
      key_vault lives in key_catalog.key_schema, which is only accessible to admins.
      Unity Catalog permission inheritance prevents regular users from querying it directly.

    Building block 2 — AES crypto functions:
      unwrap_key()  decrypts DEK material using the latest enabled KEK from key_vault.
      encrypt()     encrypts a column value using the DEK obtained via unwrap_key.
      (decrypt() is created later in create_encrypted_payroll alongside the view it serves.)

    Returns:
      kek                  — plaintext KEK (held in-memory; passed to create_secret_material)
      unwrap_key_function  — fully-qualified name of the unwrap_key SQL function
      encrypt_function     — fully-qualified name of the encrypt SQL function
      key_vault_table      — fully-qualified name of the key_vault Delta table
    """
    print("\n=== Steps 2-4: Creating key vault and AES functions ===")
    key_namespace = qualified_identifier(config.key_catalog, config.key_schema)
    key_vault_table = qualified_identifier(config.key_catalog, config.key_schema, "key_vault")
    unwrap_key_function = qualified_identifier(config.key_catalog, config.key_schema, "unwrap_key")
    encrypt_function = qualified_identifier(config.key_catalog, config.key_schema, "encrypt")

    # Generate a 192-bit KEK and base64-encode it for SQL string compatibility
    kek = b64encode(urandom(24)).decode("utf-8")

    spark.sql(f"CREATE CATALOG IF NOT EXISTS {quote_identifier(config.key_catalog)}")
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {key_namespace}")

    # key_vault stores KEK metadata and key material.
    # Only admins with privileges on key_catalog.key_schema can SELECT from it.
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

    spark.sql(
        f"""
INSERT INTO {key_vault_table} (
    created_date,
    created_time,
    last_modified_time,
    created_by,
    managed_by,
    key_name,
    key_version,
    key_enabled,
    key_type,
    key)
VALUES (
    current_date(),
    current_timestamp(),
    current_timestamp(),
    session_user(),
    session_user(),
    {sql_string(config.kek_name)},
    1,
    true,
    'KEK',
    {sql_string(kek)})
"""
    )
    show_query(spark, f"SELECT * FROM {key_vault_table}")

    # unwrap_key() selects the latest enabled KEK by name and uses it to
    # decrypt the supplied ciphertext (DEK, IV, or AAD) with AES-GCM.
    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {unwrap_key_function}(key_to_unwrap STRING, key_to_use STRING)
RETURNS STRING
RETURN aes_decrypt(
    unbase64(key_to_unwrap),
    (SELECT key FROM {key_vault_table} WHERE key_enabled AND key_name = key_to_use ORDER BY created_date DESC LIMIT 1),
    'GCM',
    'DEFAULT')
"""
    )

    # encrypt() retrieves the DEK, IV, and AAD from the secret scope via
    # unwrap_key and uses them to AES-GCM encrypt the supplied column value.
    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {encrypt_function}(col STRING)
RETURNS STRING
RETURN base64(aes_encrypt(
    col,
    {unwrap_key_function}(secret({sql_string(config.secret_scope)}, 'dek'), {sql_string(config.kek_name)}),
    'GCM',
    'DEFAULT',
    {unwrap_key_function}(secret({sql_string(config.secret_scope)}, 'iv'), {sql_string(config.kek_name)}),
    {unwrap_key_function}(secret({sql_string(config.secret_scope)}, 'aad'), {sql_string(config.kek_name)})
))
"""
    )

    return kek, unwrap_key_function, encrypt_function, key_vault_table


# ── Step 5: Secrets (Building block 3) ────────────────────────────────────────

def create_secret_material(config: DemoConfig, spark: SparkSession, kek: str) -> None:
    """
    Building block 3 — Secrets to store and access encrypted DEK material.

    Generates a fresh 192-bit DEK plus a random IV and AAD.  Each value is
    encrypted with the KEK using AES-GCM and stored in the Databricks secret
    scope.  Even if a user enumerates the scope, they only see KEK-encrypted
    ciphertext — useless without SELECT access to key_vault.

    READ access is granted to the keyvault_user principal so the AES functions
    can retrieve secrets at query time on behalf of authorised users.
    """
    print("\n=== Step 5: Generating DEK and storing encrypted material in secrets ===")

    # Generate fresh DEK (192-bit), IV (12 alphanumeric chars), and AAD (8 alphanumeric chars)
    dek = b64encode(urandom(24)).decode("utf-8")
    iv = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
    aad = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Encrypt each value with the KEK before storing; only ciphertext ever leaves this function
    encrypted_dek = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(dek)}, {sql_string(kek)}, 'GCM', 'DEFAULT'))",
    )
    encrypted_iv = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(iv)}, {sql_string(kek)}, 'GCM', 'DEFAULT'))",
    )
    encrypted_aad = query_scalar(
        spark,
        f"SELECT base64(aes_encrypt({sql_string(aad)}, {sql_string(kek)}, 'GCM', 'DEFAULT'))",
    )

    workspace_client = importlib.import_module("databricks.sdk").WorkspaceClient()
    workspace_permission = importlib.import_module("databricks.sdk.service.workspace").AclPermission.READ

    try:
        workspace_client.secrets.create_scope(scope=config.secret_scope)
    except Exception as exc:
        # Scope may already exist — log and continue
        print(f"  Secret scope note: {exc}")

    workspace_client.secrets.put_secret(scope=config.secret_scope, key="dek", string_value=encrypted_dek)
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="iv", string_value=encrypted_iv)
    workspace_client.secrets.put_secret(scope=config.secret_scope, key="aad", string_value=encrypted_aad)

    # Grant READ on the scope to the designated principal (e.g., payroll_managers group)
    workspace_client.secrets.put_acl(
        scope=config.secret_scope,
        permission=workspace_permission,
        principal=config.keyvault_user,
    )
    print(f"  Encrypted DEK material stored in secret scope '{config.secret_scope}'")
    print(f"  READ access granted to '{config.keyvault_user}'")


# ── Steps 6–8: Encrypted payroll table and decrypted view ─────────────────────

def create_encrypted_payroll(
    config: DemoConfig,
    spark: SparkSession,
    employee_hierarchy_table: str,
    employee_upn_table: str,
    encrypt_function: str,
    unwrap_key_function: str,
) -> None:
    """
    Encrypt salary values and expose them through a manager-scoped decrypted view.

    Step 6 — Create payroll_encrypted: salary column stored as AES-GCM ciphertext.
    Step 7 — Create decrypt() function with definer's rights so authorised users
             can decrypt via the view without direct access to key_vault.
    Step 8 — Create payroll_decrypted view: joins encrypted payroll with the manager
             mapping, decrypts salary inline, and filters rows to WHERE
             manager_email = current_user() — each manager sees only their own employees.
    """
    print("\n=== Steps 6-8: Creating encrypted table and manager-scoped decrypted view ===")
    payroll_encrypted_table = qualified_identifier(config.data_catalog, config.data_schema, "payroll_encrypted")
    payroll_decrypted_view = qualified_identifier(config.data_catalog, config.data_schema, "payroll_decrypted")
    decrypt_function = qualified_identifier(config.key_catalog, config.key_schema, "decrypt")

    # Step 6: salary is stored as base64-encoded AES-GCM ciphertext
    spark.sql(
        f"""
CREATE OR REPLACE TABLE {payroll_encrypted_table} AS (
SELECT
    employee_id,
    first_name,
    last_name,
    {encrypt_function}(salary) AS salary
FROM {employee_hierarchy_table})
"""
    )
    show_query(spark, f"SELECT * FROM {payroll_encrypted_table}")

    # Step 7: decrypt() wraps try_aes_decrypt — returns the plaintext on success
    # or falls back to the raw ciphertext (nvl) rather than raising an error.
    # Runs with definer's (admin) rights so end users can call it without
    # SELECT privilege on key_vault.
    spark.sql(
        f"""
CREATE OR REPLACE FUNCTION {decrypt_function}(col STRING)
RETURNS STRING
RETURN nvl(
    CAST(try_aes_decrypt(
        unbase64(col),
        {unwrap_key_function}(secret({sql_string(config.secret_scope)}, 'dek'), {sql_string(config.kek_name)}),
        'GCM',
        'DEFAULT',
        {unwrap_key_function}(secret({sql_string(config.secret_scope)}, 'aad'), {sql_string(config.kek_name)})
    ) AS STRING),
    col)
"""
    )

    # Step 8: payroll_decrypted joins encrypted salary with the manager mapping,
    # decrypts salary inline, and scopes rows to the current querying user.
    spark.sql(
        f"""
CREATE OR REPLACE VIEW {payroll_decrypted_view} AS
SELECT
    e.employee_id,
    e.first_name,
    e.last_name,
    m.manager_id,
    m.manager_email,
    {decrypt_function}(e.salary) AS salary
FROM {payroll_encrypted_table} e
JOIN {employee_upn_table} m ON e.employee_id = m.employee_id
WHERE m.manager_email = current_user()
"""
    )
    show_query(spark, f"SELECT * FROM {payroll_decrypted_view}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    config = parse_args()
    spark = SparkSession.builder.getOrCreate()

    # Steps 0–1: stage CSVs into the Unity Catalog volume and load employee tables
    stage_sample_data(config, spark)
    employee_hierarchy_table, employee_upn_table = create_employee_tables(config, spark)

    # Steps 2–4: privileged key vault + KEK + AES functions (Building blocks 1 & 2)
    kek, unwrap_key_function, encrypt_function, _ = create_key_vault(config, spark)

    # Step 5: generate DEK material and store encrypted values in secret scope (Building block 3)
    create_secret_material(config, spark, kek)

    # Steps 6–8: encrypt payroll + manager-scoped decrypted view (Building block 4)
    create_encrypted_payroll(
        config,
        spark,
        employee_hierarchy_table,
        employee_upn_table,
        encrypt_function,
        unwrap_key_function,
    )


if __name__ == "__main__":
    main()
