"""Shared classes and helpers for encryption demo scripts."""

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
    """Plaintext DEK material kept in memory only."""

    dek: str
    iv: str
    aad: str


def parse_demo_config(description: str) -> DemoConfig:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--secret-scope", default="piiscope", dest="secret_scope")
    parser.add_argument("--kek-name", default="piikeyname", dest="kek_name")
    parser.add_argument("--keyvault-user", default="payroll_managers", dest="keyvault_user")
    parser.add_argument("--data-catalog", default="consume", dest="data_catalog")
    parser.add_argument("--data-schema", default="catalog", dest="data_schema")
    parser.add_argument("--data-volume", default="synthetic_data", dest="data_volume")
    parser.add_argument("--key-catalog", default="sys", dest="key_catalog")
    parser.add_argument("--key-schema", default="crypto", dest="key_schema")
    return DemoConfig(**vars(parser.parse_args()))


class SqlTools:
    @staticmethod
    def quote_identifier(identifier: str) -> str:
        return f"`{identifier.replace('`', '``')}`"

    @staticmethod
    def qualified_identifier(*parts: str) -> str:
        return ".".join(SqlTools.quote_identifier(part) for part in parts)

    @staticmethod
    def sql_string(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"


class SparkSqlTools:
    def __init__(self, spark: SparkSession):
        self.spark = spark

    def show_query(self, label: str, query: str) -> None:
        print(f"\n  [{label}]")
        self.spark.sql(query).show(truncate=False)

    def query_scalar(self, query: str) -> str:
        row = self.spark.sql(query).first()
        if row is None:
            raise RuntimeError(f"Expected one row but got none from: {query}")
        return row[0]


class DataBootstrap:
    def __init__(self, config: DemoConfig, spark: SparkSession):
        self.config = config
        self.spark = spark
        self.sql = SparkSqlTools(spark)

    @staticmethod
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

    def stage_sample_data(self, step_title: str) -> None:
        print(f"\n=== {step_title} ===")
        data_ns = SqlTools.qualified_identifier(self.config.data_catalog, self.config.data_schema)
        self.spark.sql(
            f"CREATE CATALOG IF NOT EXISTS {SqlTools.quote_identifier(self.config.data_catalog)}"
        )
        self.spark.sql(f"CREATE SCHEMA IF NOT EXISTS {data_ns}")
        self.spark.sql(
            f"CREATE VOLUME IF NOT EXISTS "
            f"{SqlTools.qualified_identifier(self.config.data_catalog, self.config.data_schema, self.config.data_volume)}"
        )

        src = self.resolve_sample_data_dir()
        dst = Path(
            f"/Volumes/{self.config.data_catalog}/{self.config.data_schema}/{self.config.data_volume}"
        )
        dst.mkdir(parents=True, exist_ok=True)
        for csv_file in src.glob("*.csv"):
            copy2(csv_file, dst / csv_file.name)
            print(f"  Staged {csv_file.name}")

    def create_employee_tables(
        self,
        step_title: str,
        hierarchy_label: str = "employee_hierarchy",
        upn_label: str = "employee_upn",
    ) -> tuple[str, str]:
        print(f"\n=== {step_title} ===")
        hier_table = SqlTools.qualified_identifier(
            self.config.data_catalog, self.config.data_schema, "employee_hierarchy"
        )
        upn_table = SqlTools.qualified_identifier(
            self.config.data_catalog, self.config.data_schema, "employee_upn"
        )

        for table, filename in [
            (hier_table, "employee_hierarchy.csv"),
            (upn_table, "employee_upn.csv"),
        ]:
            path = (
                f"/Volumes/{self.config.data_catalog}/{self.config.data_schema}"
                f"/{self.config.data_volume}/{filename}"
            )
            self.spark.sql(
                f"""
CREATE OR REPLACE TABLE {table} AS
SELECT * FROM read_files(
    {SqlTools.sql_string(path)},
    format => 'csv',
    header => true,
    inferSchema => true)
"""
            )

        self.sql.show_query(hierarchy_label, f"SELECT * FROM {hier_table}")
        self.sql.show_query(upn_label, f"SELECT * FROM {upn_table}")
        return hier_table, upn_table


class KeyManagement:
    def __init__(self, config: DemoConfig, spark: SparkSession):
        self.config = config
        self.spark = spark
        self.sql = SparkSqlTools(spark)

    def create_key_vault(self, step_title: str) -> tuple[str, str]:
        print(f"\n=== {step_title} ===")
        key_ns = SqlTools.qualified_identifier(self.config.key_catalog, self.config.key_schema)
        key_vault_table = SqlTools.qualified_identifier(
            self.config.key_catalog, self.config.key_schema, "key_vault"
        )

        self.spark.sql(
            f"CREATE CATALOG IF NOT EXISTS {SqlTools.quote_identifier(self.config.key_catalog)}"
        )
        self.spark.sql(f"CREATE SCHEMA IF NOT EXISTS {key_ns}")
        self.spark.sql(
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
        self.spark.sql(
            f"""
INSERT INTO {key_vault_table}
    (created_date, created_time, last_modified_time, created_by, managed_by,
     key_name, key_version, key_enabled, key_type, key)
VALUES (
    current_date(), current_timestamp(), current_timestamp(),
    session_user(), session_user(),
    {SqlTools.sql_string(self.config.kek_name)}, 1, true, 'KEK', {SqlTools.sql_string(kek)})
"""
        )

        return kek, key_vault_table

    def create_unwrap_key_function(self, key_vault_table: str) -> str:
        unwrap_key_fn = SqlTools.qualified_identifier(
            self.config.key_catalog, self.config.key_schema, "unwrap_key"
        )
        self.spark.sql(
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
        return unwrap_key_fn

    def create_encrypt_function(self, unwrap_key_fn: str) -> str:
        encrypt_fn = SqlTools.qualified_identifier(
            self.config.key_catalog, self.config.key_schema, "encrypt"
        )
        self.spark.sql(
            f"""
CREATE OR REPLACE FUNCTION {encrypt_fn}(col STRING)
RETURNS STRING
RETURN base64(aes_encrypt(
    col,
    {unwrap_key_fn}(secret({SqlTools.sql_string(self.config.secret_scope)}, 'dek'), {SqlTools.sql_string(self.config.kek_name)}),
    'GCM',
    'DEFAULT',
    {unwrap_key_fn}(secret({SqlTools.sql_string(self.config.secret_scope)}, 'iv'),  {SqlTools.sql_string(self.config.kek_name)}),
    {unwrap_key_fn}(secret({SqlTools.sql_string(self.config.secret_scope)}, 'aad'), {SqlTools.sql_string(self.config.kek_name)})
))
"""
        )
        return encrypt_fn

    def create_decrypt_function(self, unwrap_key_fn: str) -> str:
        decrypt_fn = SqlTools.qualified_identifier(
            self.config.key_catalog, self.config.key_schema, "decrypt"
        )
        self.spark.sql(
            f"""
CREATE OR REPLACE FUNCTION {decrypt_fn}(col STRING)
RETURNS STRING
RETURN nvl(
    CAST(try_aes_decrypt(
        unbase64(col),
        {unwrap_key_fn}(secret({SqlTools.sql_string(self.config.secret_scope)}, 'dek'), {SqlTools.sql_string(self.config.kek_name)}),
        'GCM',
        'DEFAULT',
        {unwrap_key_fn}(secret({SqlTools.sql_string(self.config.secret_scope)}, 'aad'), {SqlTools.sql_string(self.config.kek_name)})
    ) AS STRING),
    col)
"""
        )
        return decrypt_fn

    def create_and_store_dek_material(self, step_title: str, kek: str) -> DekMaterial:
        print(f"\n=== {step_title} ===")
        dek = b64encode(urandom(24)).decode("utf-8")
        iv = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
        aad = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

        enc_dek = self.sql.query_scalar(
            f"SELECT base64(aes_encrypt({SqlTools.sql_string(dek)},  {SqlTools.sql_string(kek)}, 'GCM', 'DEFAULT'))"
        )
        enc_iv = self.sql.query_scalar(
            f"SELECT base64(aes_encrypt({SqlTools.sql_string(iv)},   {SqlTools.sql_string(kek)}, 'GCM', 'DEFAULT'))"
        )
        enc_aad = self.sql.query_scalar(
            f"SELECT base64(aes_encrypt({SqlTools.sql_string(aad)},  {SqlTools.sql_string(kek)}, 'GCM', 'DEFAULT'))"
        )

        workspace_client = importlib.import_module("databricks.sdk").WorkspaceClient()
        try:
            workspace_client.secrets.create_scope(scope=self.config.secret_scope)
        except Exception as exc:
            print(f"  Secret scope already exists or note: {exc}")

        workspace_client.secrets.put_secret(scope=self.config.secret_scope, key="dek", string_value=enc_dek)
        workspace_client.secrets.put_secret(scope=self.config.secret_scope, key="iv", string_value=enc_iv)
        workspace_client.secrets.put_secret(scope=self.config.secret_scope, key="aad", string_value=enc_aad)

        workspace_module = importlib.import_module("databricks.sdk.service.workspace")
        workspace_client.secrets.put_acl(
            scope=self.config.secret_scope,
            permission=workspace_module.AclPermission.READ,
            principal=self.config.keyvault_user,
        )

        print(f"  Encrypted DEK material stored in secret scope '{self.config.secret_scope}'")
        print(f"  READ access granted to '{self.config.keyvault_user}'")
        return DekMaterial(dek=dek, iv=iv, aad=aad)

    def update_wrapped_dek_material(self, material: DekMaterial, kek: str) -> None:
        enc_dek = self.sql.query_scalar(
            f"SELECT base64(aes_encrypt({SqlTools.sql_string(material.dek)}, {SqlTools.sql_string(kek)}, 'GCM', 'DEFAULT'))"
        )
        enc_iv = self.sql.query_scalar(
            f"SELECT base64(aes_encrypt({SqlTools.sql_string(material.iv)}, {SqlTools.sql_string(kek)}, 'GCM', 'DEFAULT'))"
        )
        enc_aad = self.sql.query_scalar(
            f"SELECT base64(aes_encrypt({SqlTools.sql_string(material.aad)}, {SqlTools.sql_string(kek)}, 'GCM', 'DEFAULT'))"
        )

        workspace_client = importlib.import_module("databricks.sdk").WorkspaceClient()
        workspace_client.secrets.put_secret(scope=self.config.secret_scope, key="dek", string_value=enc_dek)
        workspace_client.secrets.put_secret(scope=self.config.secret_scope, key="iv", string_value=enc_iv)
        workspace_client.secrets.put_secret(scope=self.config.secret_scope, key="aad", string_value=enc_aad)
