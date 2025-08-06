# Secure Sync

The secure-sync script is designed to enhance data privacy by providing end-to-end encryption (E2EE) for files before they are uploaded to cloud storage. By encrypting files locally, the script ensures that sensitive information remains secure and inaccessible to unauthorized users, including cloud service providers. This approach allows users to leverage the convenience of free cloud storage while maintaining control over their data's confidentiality.

## Getting started

```
git clone https://github.com/martynbiz/secure-sync-python.git
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

## Run as a service (linux)

This could be used to ensure that every time the system starts, secure sync is running

todo - how to access passphrase

Open a terminal and create a new service file in the /etc/systemd/system/ directory. You will need superuser privileges to do this:

```
sudo nano /etc/systemd/system/secure-sync-python.service
```

Add the following content to the service file, modifying it to fit your project:

```
[Unit]
Description=Secure sync python
After=network.target

[Service]
User=your_username
Group=your_groupname
WorkingDirectory=/path/to/secure-sync-python
ExecStart=/path/to/your/project/venv/bin/python /path/to/secure-sync-python/main.py --source-dir /path/to/source_dir --dest-dir /path/to/dest_dir
Restart=always

[Install]
WantedBy=multi-user.target
```

After creating or modifying the service file, reload the systemd manager configuration:

```
sudo systemctl daemon-reload
```

You can now start your service with the following command:

```
sudo systemctl start secure-sync-python.service
```

To ensure that your service starts automatically on boot, use the following command:

```
sudo systemctl enable secure-sync-python.service
```

You can check the status of your service to see if it is running correctly:

```
sudo systemctl status secure-sync-python.service
```

If you need to troubleshoot, you can view the logs for your service using:

```
journalctl -u secure-sync-python.service
```