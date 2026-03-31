# Data-Security-Framework-On-Databricks

A Databricks Asset Bundle demo for securing sensitive payroll data using:

- envelope encryption
- Databricks secret scopes
- Unity Catalog permissions
- user-context filtering (`current_user()`)

## Project Files

- `databricks.yml`: bundle configuration and targets
- `ARCHITECTURE.md`: architecture and security controls

### Specific Encrypting Demo

- `resources/specific_encrypting_demo_job.yml`: Databricks job definition
- `code/python/specific_encrypting_demo.py`: Python script — Steps 0–8 (encrypt, store secrets, create decrypt view)

### General Encrypting Demo

- `resources/general_encrypting_demo_job.yml`: Databricks job definition
- `code/python/general_encrypting_demo.py`: Python script — all five building blocks from the doc:
  1. Fine-grained access control (privileged key catalog)
  2. AES encrypt / decrypt functions
  3. Secrets for encrypted DEK material
  4. Column mask + row filter applied directly to the payroll table
  5. KEK rotation without rewriting data

### Sample Data

- `code/sample_data/employee_hierarchy.csv`: employee IDs, names, and salary
- `code/sample_data/employee_upn.csv`: employee-to-manager mapping

### CI/CD

- `.github/workflows/databricks-bundle.yml`: GitHub Actions workflow
  - **Pull request → `main`**: validates the `dev` bundle
  - **Push / `workflow_dispatch` → `main`**: validates, deploys, and runs the `prod` bundle

## Quick Start

Validate:

```bash
databricks bundle validate --target dev \
  --var="cluster_id=<cluster-id>" \
  --var="data_catalog=<data-catalog>" \
  --var="key_catalog=<key-catalog>" \
  --var="keyvault_user=<principal>"
```

Deploy:

```bash
databricks bundle deploy --target dev \
  --var="cluster_id=<cluster-id>" \
  --var="data_catalog=<data-catalog>" \
  --var="key_catalog=<key-catalog>" \
  --var="keyvault_user=<principal>"
```

Run specific encrypting demo job:

```bash
databricks bundle run specific_encrypting_demo_job --target dev \
  --var="cluster_id=<cluster-id>" \
  --var="data_catalog=<data-catalog>" \
  --var="key_catalog=<key-catalog>" \
  --var="keyvault_user=<principal>"
```

Run general encrypting demo job:

```bash
databricks bundle run general_encrypting_demo_job --target dev \
  --var="cluster_id=<cluster-id>" \
  --var="data_catalog=<data-catalog>" \
  --var="key_catalog=<key-catalog>" \
  --var="keyvault_user=<principal>"
```

## CI/CD Pipeline

The GitHub Actions workflow at `.github/workflows/databricks-bundle.yml` automates the full lifecycle:

- **Pull request → `main`** (dev): `bundle validate`
- **Push or `workflow_dispatch` → `main`** (prod): `bundle validate` → `bundle deploy` → `bundle run`

Required GitHub Actions variables and secrets:

- `DATABRICKS_HOST_DEV` / `DATABRICKS_HOST_PROD` (variable) — workspace URL per target
- `DATABRICKS_TOKEN_DEV` / `DATABRICKS_TOKEN_PROD` (secret) — PAT per target
- `DATABRICKS_CLUSTER_ID_DEV` / `DATABRICKS_CLUSTER_ID_PROD` (variable) — cluster ID per target
- `DATA_CATALOG_DEV` / `DATA_CATALOG_PROD` (variable) — data catalog name per target
- `KEY_CATALOG_DEV` / `KEY_CATALOG_PROD` (variable) — key catalog name per target
- `KEYVAULT_USER_DEV` / `KEYVAULT_USER_PROD` (variable) — principal granted secret `READ` per target

## Notes

- `specific_encrypting_demo.py` is the original implementation walkthrough (Steps 0–8).
- `general_encrypting_demo.py` demonstrates all five building blocks from the "Envelope Encryption with Unity Catalog" article, including column masks and key rotation.
- See `ARCHITECTURE.md` for design details, controls, and risks.
