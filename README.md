# About

Parse sslscan output and generate evidences using openssl

# Download

## [Click here to download latest version](https://raw.githubusercontent.com/skylazart/sslscanutils/master/src/sslscanutil.py)

# Help

```
./sslscanutil.py -h
Usage: sslscanutil.py [options]

Options:
  -h, --help            show this help message and exit
  -H HOST, --host=HOST  Format: hostname or IP address
  -P PORT, --port=PORT  Format: destination port address
  -S SSH, --ssh=SSH     Format: 'ssh user@host'
  -O OUTPUT, --output=OUTPUT
                        Format: report.html
  -I INPUT, --input=INPUT
                        Format: file containing lines
                        host:port:path_to_report.html
  --openssl=OPENSSL_PATH
                        Custom path to openssl
  --sslscan=SSLSCAN_PATH
                        Custom path to sslscan
  --curl=CURL_PATH      Custom path to curl
  --nmap=NMAP_PATH      Custom path to nmap
  --enable-recon        Enable Nmap recon - default is disabled
```
  
# Examples
* Using sslscan remotely throughout a ssh session

```
./scanutil.py -H target -P 443 -S 'ssh user@remoteshell.com'
```

* Using sslcan locally

```
./scanutil.py -H target -P 443
```

* Batch mode

```
echo "host1:443:host1.html" > batch.txt
echo "host2:443:host2.html" >> batch.txt

./sslscanutil.py -I batch.txt
or
./sslscanutil.py -I batch.txt -S 'ssh root@vrpt'
```

# Screenshot

![screenshot](https://git.trustwave.com/fsantos/sslscanutil/raw/master/screenshot/scanresult.png?raw=true)

# Status

This tool is not only a SSL checker. We are already scanning for HSTS and looking for HTTP port opened.
Any interesting idea to improve the software? Let me know or send a PR.

# Missing features

* Allow customizing openssl and curl path (locally or remote)
* Check for expired SSL certificates

Please, send your ideas!

Thanks
