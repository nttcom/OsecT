FROM ubuntu:20.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /home/work
RUN mkdir /home/work/django
RUN mkdir /home/work/uwsgi
COPY work/ /home/work
WORKDIR /home/work

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    bison \
    cmake \
    cron \
    cargo \
    build-essential \
    flex \
    gawk \
    gcc \
    g++ \
    libmount-dev \
    libpcre3-dev \
    libyaml-dev \
    libpcap0.8-dev \
    libjansson-dev \
    libpcap-dev \
    libssl-dev \
    libmaxminddb-dev \
    ninja-build \
    make \
    pkg-config \
    python3-dev \
    python3-pip \
    python3-yaml \
    python3-semantic-version \
    python3-setuptools \
    python3-git \
    rustc \
    supervisor \
    swig \
    tshark \
    tzdata \
    vim \
    wget \
    zlib1g-dev\
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/*

RUN echo "${TZ}" > /etc/timezone \
   && dpkg-reconfigure -f noninteractive tzdata

# Zeekのインストール。
RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
RUN cd zeek && ./configure --prefix=/opt/zeek && make && make install
RUN cd ~/ || exit

RUN mkdir /opt/ot_tools

# Suricataのインストール。
RUN wget https://www.openinfosecfoundation.org/download/suricata-6.0.4.tar.gz
RUN tar -xf suricata-6.0.4.tar.gz
RUN cd /home/work/suricata-6.0.4 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && make install-full
RUN cd ~/ || exit
RUN wget http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz
RUN tar -xzvf emerging.rules.tar.gz
RUN mkdir -p /var/lib/suricata
RUN cp -pr rules /var/lib/suricata/

# Zeel、Suricata、Yafの資材配置。SaaS版ではコメントアウトすること。
RUN cp -p ot_tools/broscript/conn/__load__.zeek /opt/zeek/share/zeek/base/protocols/conn/
RUN cp -p ot_tools/broscript/conn/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/conn/
RUN cp -p ot_tools/broscript/http/__load__.zeek /opt/zeek/share/zeek/base/protocols/http/
RUN cp -p ot_tools/broscript/http/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/http/
RUN cp -p ot_tools/broscript/arp.zeek /opt/zeek/share/zeek/base/protocols/
RUN cp -p ot_tools/broscript/ns.zeek /opt/zeek/share/zeek/base/protocols/
RUN cp -p ot_tools/*.sh /opt/ot_tools/
RUN cp -p ot_tools/suricata.yaml /opt/ot_tools/
RUN cp -p ot_tools/tsharkfields2bacnetservicelog_dict.awk /opt/ot_tools/
RUN cp -p ot_tools/yaf.awk /opt/ot_tools/

RUN cp -pr ot_tools/p0f /opt/

RUN apt purge -y python3-yaml

RUN python3.8 -m pip install --upgrade pip --no-cache-dir
RUN python3.8 -m pip install setuptools==59.8.0
RUN python3.8 -m pip install -r requirements.txt --no-cache-dir
ENV PATH $PATH:/opt/zeek/bin
RUN zkg autoconfig && zkg install --force zeek-plugin-bacnet
RUN mkdir /var/log/ot_tools

# Yafのインストール。
RUN wget https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz
RUN tar xvfJ glib-2.60.7.tar.xz
RUN cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig
RUN cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz
RUN cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install
RUN cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz
RUN cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig


RUN mv crontab /root/crontab
RUN crontab /root/crontab

RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt

RUN mv supervisord.conf /etc/supervisor/conf.d/
