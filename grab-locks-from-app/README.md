# TTLock DB Secrets Extractor

This script extracts lock secrets from the TTLock app database.

## Steps

1. Log in to the TTLock app once on the rooted device or emulator.
   There is no need to re-pair locks — secrets will be transferred from your account.

2. Copy the database files from the device:

   ```
   /data/data/com.tongtongsuo.app/databases/newsciener.db*
   ```

   Place them into this directory.

3. Run the script:

   ```bash
   python3 db2locks.py newsciener.db
   ```

## Output

The script will create or update a file named:

```
locks.json
```

This file can be used with the `ttlock-sdk-py` CLI.
