# Data-Security-Framework-On-Databricks

A Databricks Asset Bundle demo for securing sensitive payroll data using:
- envelope encryption
- Databricks secret scopes
- Unity Catalog permissions
- user-context filtering (`current_user()`)

## Project Files
- `databricks.yml`: bundle configuration and targets
- `resources/pii_data_process_job.yml`: job definition
- `code/python/pii_data_process.py`: notebook workflow (Steps 0-8)
- `ARCHITECTURE.md`: architecture and security controls

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

Run:

```bash
databricks bundle run pii_data_process_job.yml --target dev \
  --var="cluster_id=<cluster-id>" \
  --var="data_catalog=<data-catalog>" \
  --var="key_catalog=<key-catalog>" \
  --var="keyvault_user=<principal>"
```

## Notes
- The notebook contains the full implementation walkthrough.
- See `ARCHITECTURE.md` for design details, controls, and risks.
