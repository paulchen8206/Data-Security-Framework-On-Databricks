"""General Encrypting Demo — Unity Catalog Encryption Script.

Showcases the five building blocks for general column-level encryption
with Unity Catalog:

  1. Fine-grained access control.
  2. AES functions.
  3. Secrets for DEK material.
  4. Column mask + row filter.
  5. Key rotation without data rewrite.
"""

from base64 import b64encode
from os import urandom

from pyspark.sql import SparkSession

from common.utils import DataBootstrap
from common.utils import DekMaterial
from common.utils import DemoConfig
from common.utils import KeyManagement
from common.utils import SparkSqlTools
from common.utils import SqlTools
from common.utils import parse_demo_config


def create_encrypted_payroll(
    config: DemoConfig,
    spark: SparkSession,
    hier_table: str,
    upn_table: str,
    encrypt_fn: str,
) -> str:
    print("\n=== Step 6: Creating encrypted payroll table ===")
    payroll_table = SqlTools.qualified_identifier(config.data_catalog, config.data_schema, "payroll_data")

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

    SparkSqlTools(spark).show_query(
        "payroll_data — raw table (no mask): salary is ciphertext",
        f"SELECT * FROM {payroll_table} LIMIT 5",
    )
    return payroll_table


def apply_column_mask_and_row_filter(
    config: DemoConfig,
    spark: SparkSession,
    payroll_table: str,
    decrypt_fn: str,
) -> None:
    print("\n=== Step 7: Applying column mask and row filter ===")

    row_filter_fn = SqlTools.qualified_identifier(
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

    spark.sql(f"ALTER TABLE {payroll_table} ALTER COLUMN salary SET MASK {decrypt_fn}")
    print(f"  Column mask applied on salary  -> {decrypt_fn}")

    spark.sql(f"ALTER TABLE {payroll_table} SET ROW FILTER {row_filter_fn} ON (manager_email)")
    print(f"  Row filter applied on manager_email -> {row_filter_fn}")

    SparkSqlTools(spark).show_query(
        "payroll_data — with mask active (salary decrypted, rows filtered to current_user)",
        f"SELECT * FROM {payroll_table}",
    )


def rotate_kek(
    config: DemoConfig,
    spark: SparkSession,
    dek_material: DekMaterial,
    key_vault_table: str,
    payroll_table: str,
) -> None:
    print("\n=== Step 8: Key rotation — new KEK, no data rewrite ===")
    sql = SparkSqlTools(spark)
    key_manager = KeyManagement(config, spark)

    print("  payroll_data row count (before): ", end="")
    print(sql.query_scalar(f"SELECT COUNT(*) FROM {payroll_table}"))

    new_kek = b64encode(urandom(24)).decode("utf-8")
    key_manager.update_wrapped_dek_material(dek_material, new_kek)
    print("  Secrets updated with new KEK-wrapped DEK material")

    spark.sql(
        f"""
UPDATE {key_vault_table}
SET key_enabled = false, last_modified_time = current_timestamp()
WHERE key_name = {SqlTools.sql_string(config.kek_name)} AND key_version = 1
"""
    )

    spark.sql(
        f"""
INSERT INTO {key_vault_table}
    (created_date, created_time, last_modified_time, created_by, managed_by,
     key_name, key_version, key_enabled, key_type, key)
VALUES (
    current_date(), current_timestamp(), current_timestamp(),
    session_user(), session_user(),
    {SqlTools.sql_string(config.kek_name)}, 2, true, 'KEK', {SqlTools.sql_string(new_kek)})
"""
    )
    print("  key_vault: v1 disabled, v2 inserted")

    sql.show_query(
        "key_vault after rotation",
        f"SELECT id, key_name, key_version, key_enabled, key_type FROM {key_vault_table}",
    )

    print("\n  Verifying column mask still decrypts correctly after rotation...")
    sql.show_query(
        "payroll_data after key rotation (salary still decrypts via new KEK, table unchanged)",
        f"SELECT * FROM {payroll_table}",
    )
    print("  Key rotation complete.")


def main() -> None:
    config = parse_demo_config("Envelope Encryption with Unity Catalog demo.")
    spark = SparkSession.builder.getOrCreate()

    sql = SparkSqlTools(spark)
    data_bootstrap = DataBootstrap(config, spark)
    key_manager = KeyManagement(config, spark)

    data_bootstrap.stage_sample_data("Step 1: Staging sample data")
    hier_table, upn_table = data_bootstrap.create_employee_tables(
        "Step 2: Creating employee tables"
    )

    kek, key_vault_table = key_manager.create_key_vault(
        "Step 3: Setting up key vault in privileged catalog"
    )
    sql.show_query(
        "key_vault (admin view — regular users cannot access this table)",
        f"SELECT id, key_name, key_version, key_enabled, key_type FROM {key_vault_table}",
    )

    print("\n=== Step 4: Creating AES crypto functions ===")
    unwrap_key_fn = key_manager.create_unwrap_key_function(key_vault_table)
    encrypt_fn = key_manager.create_encrypt_function(unwrap_key_fn)
    decrypt_fn = key_manager.create_decrypt_function(unwrap_key_fn)
    print(f"  Created: {unwrap_key_fn}")
    print(f"  Created: {encrypt_fn}")
    print(f"  Created: {decrypt_fn}  <- will be registered as column mask")

    dek_material = key_manager.create_and_store_dek_material(
        "Step 5: Generating DEK and storing encrypted material in secrets",
        kek,
    )

    payroll_table = create_encrypted_payroll(config, spark, hier_table, upn_table, encrypt_fn)
    apply_column_mask_and_row_filter(config, spark, payroll_table, decrypt_fn)
    rotate_kek(config, spark, dek_material, key_vault_table, payroll_table)


if __name__ == "__main__":
    main()