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
* Using sslscan remotely throughout a ssh session

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

# Common problems

If you are using a Kali Linux to run the openssl commands remotely, you may see the following error:

```
unknown option -ssl3
```

In this case, I found this instructions to fix it:
https://bugs.kali.org/view.php?id=3190

Basically:

```
apt-get update
apt-get build-dep openssl
apt-get source openssl
cd openssl-1.0.2g
... edit debian/rules, remove no-ssl2 nossl3 no-ssl3-method from CONFARGS on line 29 ...

dpkg-buildpackage
cd ..
dpkg -i openssl_1.0.2g-1_amd64.deb
dpkg -i libssl1.0.2_1.0.2g-1_amd64.deb
```

# Missing features

* Allow customizing openssl and curl path (locally or remote)
* Check expired SSL certificates

Thanks
