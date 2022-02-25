FROM ubuntu:20.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/work
COPY work/ /home/work

RUN apt update \
 && apt install -y --no-install-recommends \
    python3-pip \
    tcpdump \
    tzdata \
#    vim \
 && apt -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata \
 && mkdir /opt/ot_tools \
 && cp -p ot_tools/*.sh /opt/ot_tools/ \
 && python3.8 -m pip install --upgrade pip \
 && python3.8 -m pip install setuptools==59.8.0 \
 && python3.8 -m pip install -r requirements.txt \
 && apt purge -y python3-pip
WORKDIR /opt/edge_tcpdump
