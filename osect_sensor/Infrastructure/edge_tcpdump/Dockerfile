FROM ubuntu:20.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /home/work
COPY work/ /home/work
WORKDIR /home/work

RUN apt update \
 && apt install -y --no-install-recommends \
    python3-pip \
    tcpdump \
    tzdata \
    vim \
 && apt -y clean \
 && rm -rf /var/lib/apt/lists/*

RUN echo "${TZ}" > /etc/timezone \
   && dpkg-reconfigure -f noninteractive tzdata

RUN mkdir /opt/ot_tools

RUN cp -p ot_tools/*.sh /opt/ot_tools/

RUN python3.8 -m pip install --upgrade pip
RUN python3.8 -m pip install setuptools==59.8.0
RUN python3.8 -m pip install -r requirements.txt

WORKDIR /opt/edge_tcpdump
