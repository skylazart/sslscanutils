# About

Parse sslscan output and generate evidences using openssl

# Help

```
./scanutil.py -h
Usage: scanutil.py [options]

Options:
  -h, --help            show this help message and exit
  -H HOST, --host=HOST  Format: hostname or IP address
  -P PORT, --port=PORT  Format: destination port address
  -S SSH, --ssh=SSH     Format: 'ssh user@host'
```
  
# Examples
* Using sslscan remotely throughout an ssh session

```
./scanutil.py -H target -P 443 -S 'ssh user@remoteshell.com'
```

* Using sslcan locally

```
./scanutil.py -H target -P 443
```

# Status

There are some tests missing, like SSLv3 for example. If you are using this tool and want to contribute, 
please open an issue including the sslscan output.

Thanks
