"""Specific Encrypting Demo — Steps 0-8 walkthrough for column-level encryption.

This script demonstrates a view-based approach where decrypted salary is exposed
through a manager-scoped view.
"""

from pyspark.sql import SparkSession

from common.utils import DataBootstrap
from common.utils import DemoConfig
from common.utils import KeyManagement
from common.utils import SparkSqlTools
from common.utils import SqlTools
from common.utils import parse_demo_config


def create_encrypted_payroll(
    config: DemoConfig,
    spark: SparkSession,
    employee_hierarchy_table: str,
    employee_upn_table: str,
    encrypt_function: str,
    decrypt_function: str,
) -> None:
    print("\n=== Steps 6-8: Creating encrypted table and manager-scoped decrypted view ===")
    payroll_encrypted_table = SqlTools.qualified_identifier(
        config.data_catalog, config.data_schema, "payroll_encrypted"
    )
    payroll_decrypted_view = SqlTools.qualified_identifier(
        config.data_catalog, config.data_schema, "payroll_decrypted"
    )

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
    SparkSqlTools(spark).show_query(
        "payroll_encrypted",
        f"SELECT * FROM {payroll_encrypted_table}",
    )

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
    SparkSqlTools(spark).show_query(
        "payroll_decrypted",
        f"SELECT * FROM {payroll_decrypted_view}",
    )


def main() -> None:
    config = parse_demo_config(
        "Secure payroll data with Databricks encryption and row filtering."
    )
    spark = SparkSession.builder.getOrCreate()

    data_bootstrap = DataBootstrap(config, spark)
    key_manager = KeyManagement(config, spark)
    sql = SparkSqlTools(spark)

    data_bootstrap.stage_sample_data("Step 0: Staging sample data")
    employee_hierarchy_table, employee_upn_table = data_bootstrap.create_employee_tables(
        "Step 1: Creating employee tables"
    )

    print("\n=== Steps 2-4: Creating key vault and AES functions ===")
    kek, key_vault_table = key_manager.create_key_vault("Step 2: Creating key vault table")
    sql.show_query("key_vault", f"SELECT * FROM {key_vault_table}")

    unwrap_key_function = key_manager.create_unwrap_key_function(key_vault_table)
    encrypt_function = key_manager.create_encrypt_function(unwrap_key_function)

    key_manager.create_and_store_dek_material(
        "Step 5: Generating DEK and storing encrypted material in secrets",
        kek,
    )
    decrypt_function = key_manager.create_decrypt_function(unwrap_key_function)

    create_encrypted_payroll(
        config,
        spark,
        employee_hierarchy_table,
        employee_upn_table,
        encrypt_function,
        decrypt_function,
    )


if __name__ == "__main__":
    main()