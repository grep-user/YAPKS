FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3.8 \
      openjdk-11-jdk-headless \
      python3-pip \
      unzip \
 && rm -rf /var/lib/apt/lists/*

RUN python3.8 -m pip install mobsfscan libsast pyaxmlparser

ADD https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip /tmp/jadx.zip

RUN unzip /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

COPY analyze.py apkleaks apps apkleaks.py config dvm_permissions.py firebase_scanner.py outputs rules run.py sample.mobsf setup.py /home/YAPKS/
COPY apkleaks/ /home/YAPKS/apkleaks/
COPY apps/ /home/YAPKS/apps/
COPY config/ /home/YAPKS/config/
COPY outputs/ /home/YAPKS/outputs/
COPY rules/ /home/YAPKS/rules/

