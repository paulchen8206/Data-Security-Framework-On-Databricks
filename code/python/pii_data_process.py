# Databricks notebook source
# MAGIC %md
# MAGIC # Sensitive Data ManagementDemo
# MAGIC 
# MAGIC This notebook contains the full walkthrough to secure payroll PII data with encryption, secrets, and user-context filtering on Databricks.
# MAGIC 
# MAGIC ## Prerequisites
# MAGIC - Databricks CLI v0.218.0 or newer
# MAGIC - A configured Databricks CLI authentication profile
# MAGIC - An existing Databricks cluster ID
# MAGIC - Permissions to create catalogs, schemas, volumes, tables, views, and functions
# MAGIC 
# MAGIC 
# MAGIC ## Demo Flow
# MAGIC 0. Secret scope, KEK name, and key access principal inputs
# MAGIC 1. Prepare employee hierarchy and employee UPN tables
# MAGIC 2. Generate KEK and create key vault table
# MAGIC 3. Encrypt DEK material and store in secret scope
# MAGIC 4. Create unwrap and encrypt functions
# MAGIC 5. Build encrypted payroll table
# MAGIC 6. Create decrypt function
# MAGIC 7. Create manager-filtered decrypted view
# MAGIC 8. Query results and validate decryption behavior

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 0
# MAGIC Secret Scope, Key Encryption Key Name and User/Group to Access the Key as Inputs 
# MAGIC

# COMMAND ----------

dbutils.widgets.text(name="secret_scope", defaultValue="piiscope", label="The secret scope to use for DEKs")
dbutils.widgets.text(name="kek_name", defaultValue="piikeyname", label="The name to use for our KEK")
dbutils.widgets.text(name="keyvault_user", defaultValue="payroll_managers", label="The username to grant unprivileged access to decrypt the data")
dbutils.widgets.text(name="data_catalog", defaultValue="consume", label="The Unity Catalog catalog to use for demo data")
dbutils.widgets.text(name="data_schema", defaultValue="catalog", label="The Unity Catalog schema to use for demo data")
dbutils.widgets.text(name="data_volume", defaultValue="synthetic_data", label="The Unity Catalog volume to stage bundled CSV files into")
dbutils.widgets.text(name="key_catalog", defaultValue="sys", label="The Unity Catalog catalog to use for the key vault")
dbutils.widgets.text(name="key_schema", defaultValue="crypto", label="The Unity Catalog schema to use for the key vault")

from pathlib import Path, PurePosixPath
from shutil import copy2


def quote_identifier(identifier: str) -> str:
    return f"`{identifier.replace('`', '``')}`"


def qualified_identifier(*parts: str) -> str:
    return ".".join(quote_identifier(part) for part in parts)


data_catalog = dbutils.widgets.get("data_catalog")
data_schema = dbutils.widgets.get("data_schema")
data_volume = dbutils.widgets.get("data_volume")
key_catalog = dbutils.widgets.get("key_catalog")
key_schema = dbutils.widgets.get("key_schema")

data_namespace = qualified_identifier(data_catalog, data_schema)
employee_hierarchy_table = qualified_identifier(data_catalog, data_schema, "employee_hierarchy")
employee_upn_table = qualified_identifier(data_catalog, data_schema, "employee_upn")
payroll_encrypted_table = qualified_identifier(data_catalog, data_schema, "payroll_encrypted")
payroll_decrypted_view = qualified_identifier(data_catalog, data_schema, "payroll_decrypted")
key_namespace = qualified_identifier(key_catalog, key_schema)
key_vault_table = qualified_identifier(key_catalog, key_schema, "key_vault")
unwrap_key_function = qualified_identifier(key_catalog, key_schema, "unwrap_key")
encrypt_function = qualified_identifier(key_catalog, key_schema, "encrypt")
decrypt_function = qualified_identifier(key_catalog, key_schema, "decrypt")

spark.sql(f"CREATE CATALOG IF NOT EXISTS {quote_identifier(data_catalog)}")
spark.sql(f"CREATE SCHEMA IF NOT EXISTS {data_namespace}")
spark.sql(f"CREATE VOLUME IF NOT EXISTS {qualified_identifier(data_catalog, data_schema, data_volume)}")

notebook_path = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
bundle_root = PurePosixPath(notebook_path).parent.parent
workspace_data_dir = Path("/Workspace") / bundle_root.relative_to("/") / "sample_data"
volume_data_dir = Path(f"/Volumes/{data_catalog}/{data_schema}/{data_volume}")
volume_data_dir.mkdir(parents=True, exist_ok=True)

for source_file in workspace_data_dir.glob("*.csv"):
    copy2(source_file, volume_data_dir / source_file.name)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 1
# MAGIC Prepare the sample employee and manager tables.

# COMMAND ----------

employee_hierarchy_path = f"/Volumes/{data_catalog}/{data_schema}/{data_volume}/employee_hierarchy.csv"

spark.sql(f"""
CREATE OR REPLACE TABLE {employee_hierarchy_table} AS
SELECT * FROM read_files(
    '{employee_hierarchy_path}',
    format => 'csv',
    header => true,
    inferSchema => true)
""")

# COMMAND ----------

display(spark.sql(f"SELECT * FROM {employee_hierarchy_table}"))

# COMMAND ----------

employee_upn_path = f"/Volumes/{data_catalog}/{data_schema}/{data_volume}/employee_upn.csv"

spark.sql(f"""
CREATE OR REPLACE TABLE {employee_upn_table} AS
SELECT * FROM read_files(
    '{employee_upn_path}',
    format => 'csv',
    header => true,
    inferSchema => true)
""")

# COMMAND ----------

display(spark.sql(f"SELECT * FROM {employee_upn_table}"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 2
# MAGIC Generate a Key Encryption Key (KEK) and create a key_vault table to store it in. A dedicated catalog and schema are used.

# COMMAND ----------

from base64 import b64encode
from os import urandom

kek = b64encode(urandom(24)).decode('utf-8')

# COMMAND ----------

spark.sql(f"CREATE CATALOG IF NOT EXISTS {quote_identifier(key_catalog)}")
spark.sql(f"CREATE SCHEMA IF NOT EXISTS {key_namespace}")
spark.sql(f"""
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
""")

# COMMAND ----------

kek_name = dbutils.widgets.get("kek_name")

spark.sql(f"""
    INSERT INTO {key_vault_table} (created_date, created_time, last_modified_time, created_by, managed_by, key_name, key_version, key_enabled, key_type, key)
    VALUES (current_date(), current_timestamp(), current_timestamp(), session_user(), session_user(), '{kek_name}', 1, True, 'KEK', '{kek}')""")

# COMMAND ----------

display(spark.sql(f"SELECT * FROM {key_vault_table}"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 3
# MAGIC Use the KEK to encrypt our Data Encryption Key (DEK) and store the encrypted DEK as a secret (along with Initilisation Vector and Additionally Authenticated Data)

# COMMAND ----------

import string
import random

dek = b64encode(urandom(24)).decode('utf-8')
iv = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
aad = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

encrypted_dek = spark.sql(f"SELECT base64(aes_encrypt('{dek}', '{kek}', 'GCM', 'DEFAULT'))").first()[0]
encrypted_iv = spark.sql(f"SELECT base64(aes_encrypt('{iv}', '{kek}', 'GCM', 'DEFAULT'))").first()[0]
encrypted_aad = spark.sql(f"SELECT base64(aes_encrypt('{aad}', '{kek}', 'GCM', 'DEFAULT'))").first()[0]

# COMMAND ----------

from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

secret_scope = dbutils.widgets.get("secret_scope")

try:
    w.secrets.create_scope(scope=secret_scope)
except Exception as e:
    print(e)

w.secrets.put_secret(scope=secret_scope, key='dek', string_value=encrypted_dek)
w.secrets.put_secret(scope=secret_scope, key='iv', string_value=encrypted_iv)
w.secrets.put_secret(scope=secret_scope, key='aad', string_value=encrypted_aad)

# COMMAND ----------

# grant READ to the users

from databricks.sdk.service import workspace

w.secrets.put_acl(scope=secret_scope, permission=workspace.AclPermission.READ, principal=dbutils.widgets.get("keyvault_user"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 4
# MAGIC Create crypto functions to unwrap our keys and encrypt the data

# COMMAND ----------

spark.sql(f"""
CREATE OR REPLACE FUNCTION {unwrap_key_function}(key_to_unwrap STRING, key_to_use STRING)
RETURNS STRING
RETURN aes_decrypt(
    unbase64(key_to_unwrap),
    (SELECT key FROM {key_vault_table} WHERE key_enabled AND key_name = key_to_use ORDER BY created_date DESC LIMIT 1),
    'GCM',
    'DEFAULT')
""")

# COMMAND ----------

kek_name = dbutils.widgets.get("kek_name")

spark.sql(f"""CREATE OR REPLACE FUNCTION {encrypt_function}(col STRING)
RETURNS STRING
RETURN
        base64(aes_encrypt(col,
        {unwrap_key_function}(secret('{secret_scope}', 'dek'), '{kek_name}'),
        'GCM',
    'DEFAULT',
        {unwrap_key_function}(secret('{secret_scope}', 'iv'), '{kek_name}'),
        {unwrap_key_function}(secret('{secret_scope}', 'aad'), '{kek_name}')
    ))""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 5
# MAGIC Create a table employee_encrypt with the salary information encrypted

# COMMAND ----------

spark.sql(f"""
CREATE OR REPLACE TABLE {payroll_encrypted_table} AS (
SELECT
employee_id,
first_name,
last_name,
{encrypt_function}(salary) AS salary
FROM {employee_hierarchy_table})
""")

# COMMAND ----------

display(spark.sql(f"SELECT * FROM {payroll_encrypted_table}"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 6
# MAGIC Create a crypto function to decrypt the data

# COMMAND ----------

spark.sql(f"""CREATE OR REPLACE FUNCTION {decrypt_function}(col STRING)
RETURNS STRING
RETURN
    nvl(CAST(try_aes_decrypt(unbase64(col),
    {unwrap_key_function}(secret('{secret_scope}', 'dek'), '{kek_name}'),
    'GCM',
    'DEFAULT',
    {unwrap_key_function}(secret('{secret_scope}', 'aad'), '{kek_name}')) AS STRING),
    col)
    """)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 7
# MAGIC Apply the decrypt function to create a view which allows the manager to see their employee data only

# COMMAND ----------

spark.sql(f"""
CREATE OR REPLACE VIEW {payroll_decrypted_view} AS
SELECT e.employee_id, e.first_name, e.last_name, m.manager_id, m.manager_email,
{decrypt_function}(e.salary) AS salary
FROM {payroll_encrypted_table} e JOIN {employee_upn_table} m ON e.employee_id = m.employee_id
WHERE m.manager_email = current_user()
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 8
# MAGIC Query the data and confirm that the data is decryped as expected

# COMMAND ----------

display(spark.sql(f"SELECT * FROM {payroll_decrypted_view}"))

# COMMAND ----------

# MAGIC %md
# MAGIC