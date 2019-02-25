## djif-base-inspec-windows
Inspec profile for base DJ Windows image.

### Upload to Chef Automate server
1. Clone the repo:
```
git clone git@github.dowjones.net:infrasec-automation/djif-base-inspec-windows.git
```

2. Create an archive: 
```
inspec archive djif-base-inspec-windows
```

3. Login to Chef Automate Server:
```
inspec compliance login <ca_server_url> --insecure  --ent='default' --user='admin' --dctoken='<ca_data_collector_token>'
```

4. Upload the archive to Chef Automate server
```
inspec compliance upload djif-base-inspec-windows-<version>.tar.gz
```
