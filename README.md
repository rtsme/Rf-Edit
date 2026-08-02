Install Python
https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe

Then run start.bat

Press open server and select your entire server folder.

*Create Repo -- Only to make a new repo out of what is currently in the server. You dont need this probably*

Clone the repo the team is working on down to your machine.

press open repo on that folder.

Make changes as normal in whatever IDE you want on not the server repo, press preview changes to see if there are any issues. THey are mostly caused by messing with the formatting.

If there arent any issues push your changes to a new branch and make a PR into main.

Approve the PR, the server will pick up the changes, the tool on there will make the .dat files and apply them to the server ad bring it back up.

*you can either now pull the server down again, or press build to server to have the same server files that are running*


## Command line if you prefer to UI

```
python rf_repo.py --repo D:\rf-data --server "D:\rf\1_Server AOP" create
python rf_repo.py --repo D:\rf-data status
python rf_repo.py --repo D:\rf-data build --confirm
python rf_repo.py --repo D:\rf-data sync-files      # refresh .ini only
python verify_all.py [folder]
```

`build` without `--confirm` only lists what would change.
