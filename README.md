## Command line

```
python rf_repo.py --repo D:\rf-data --server "D:\rf\1_Server AOP" create
python rf_repo.py --repo D:\rf-data status
python rf_repo.py --repo D:\rf-data build --confirm
python rf_repo.py --repo D:\rf-data sync-files      # refresh .ini only
python verify_all.py [folder]
```

`build` without `--confirm` only lists what would change.