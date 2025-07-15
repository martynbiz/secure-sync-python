# Secure Sync

The secure-sync script is designed to enhance data privacy by providing end-to-end encryption (E2EE) for files before they are uploaded to cloud storage. By encrypting files locally, the script ensures that sensitive information remains secure and inaccessible to unauthorized users, including cloud service providers. This approach allows users to leverage the convenience of free cloud storage while maintaining control over their data's confidentiality.

## Getting started

```
git clone ...
cd secure-sync-python
pip install -r requirements.txt
```

Encrypt files

```
python .\main.py --source-dir ./Documents --dest-dir ./pCloud --mode enc
```

By passing --force will overwrite any files in dest dir that weren't found in source dir

Decrypt files

```
python .\main.py --source-dir ./Documents --dest-dir ./pCloud --mode dec
```

By passing --force will overwrite any files in source dir that weren't found in dest dir

Watch files

```
python .\main.py --source-dir ./Documents --dest-dir ./pCloud
```

## Unit testing

todo