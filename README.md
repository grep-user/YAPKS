<<<<<<< HEAD

# YAPKS - Yet Another APK Scanner

This is combination of multiple android security scanner tools.

1. [apkleaks](https://github.com/dwisiswant0/apkleaks/tree/master): scanning secrets and URIs from apk
2. [mobsfscan](https://github.com/MobSF/mobsfscan): SAST scanner to flag security findings using semgrep rules
3. [semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security): OWASP MASTG rules, used few sets of rules here.
4. [firebase-scanner](https://github.com/arxenix/firebase-scanner) [In progress]: Firebase misconfiguration if firebase is used.

- [Setup](#setup)

```bash
pip install requirements.txt

# installing jadx and make sure jadx is in path 
wget https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip -O /tmp/jadx.zip

unzip /tmp/jadx.zip -d /opt/jadx

ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
```

- [Usage](#Usage)

```bash
python3 run.py apps/app-debug.apk

```

> [!TIP]
> Once the scan is completed, the result will be stored in $PWD/outputs/ directory.

```
apkleaks result: pkgname-DD-MM-YYYY--apkleaks.json
mobsfscan sast scan result: pkgname-DD-MM-YYYY--scan.json
```

- [Docker](#docker)

Added Dockerfile for easy usage.

```bash
docker build -t yapks .

docker run -it yapks /bin/bash

python3 run.py /home/YAPKS/app-debug.apk

```


**Note: The rules added in rules/ is solely my decision to include only specific rules from semgrep-rules-android-security. You can add all the rules and run it.**


