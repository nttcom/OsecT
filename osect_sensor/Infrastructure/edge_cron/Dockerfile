FROM ubuntu:20.04 As build-env
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/work
COPY work/ /home/work
RUN mkdir /home/work/django && mkdir /home/work/uwsgi

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
    zlib1g-dev \
    libpcre3 \
    libpcre3-dbg \
    libyaml-0-2 \
    zlib1g \
    libmagic-dev \
#    libjansson \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
  && dpkg-reconfigure -f noninteractive tzdata

# Zeekのインストール。
RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
#WORKDIR /home/work/zeek
RUN cd zeek && ./configure --prefix=/opt/zeek && make && make install
WORKDIR /
RUN mkdir /opt/ot_tools


WORKDIR /home/work
#suricataのインストール
#RUN wget https://www.openinfosecfoundation.org/download/suricata-6.0.4.tar.gz \
# && tar -xf suricata-6.0.4.tar.gz \
# && cd /home/work/suricata-6.0.4 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && make install-full
#WORKDIR /home/work


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
RUN mkdir /var/log/ot_tools
ENV PATH $PATH:/opt/zeek/bin

# Yafのインストール。
RUN wget https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz \
 && tar xvfJ glib-2.60.7.tar.xz \
 && cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig \
 && cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz \
 && cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install \
 && cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz \
 && cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig

RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt
RUN mv supervisord.conf /etc/supervisor/conf.d/

#本番イメージ
FROM ubuntu:20.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/work
COPY work/ /home/work
RUN mkdir /home/work/django && mkdir /home/work/uwsgi

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    cron \
    cmake \
    gawk \
    gcc \
    g++ \
    libmount-dev \
    libyaml-dev \
    libjansson-dev \
    libpcap-dev \
    make \
    ninja-build \
    python3-pip \
    python3-yaml \
    python3-git \
    pkg-config \
    supervisor \
    tshark \
    tzdata \
    wget \
    libpcre3 \
    libpcre3-dbg \
    libyaml-0-2 \
    zlib1g \
    libmagic-dev \
    software-properties-common \
    zlib1g-dev\
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata

#zeekのバイナリファイルをコピー
COPY --from=build-env /opt/zeek/bin /opt/zeek/bin
COPY --from=build-env /opt/zeek/lib /opt/zeek/lib
COPY --from=build-env /opt/zeek/etc /opt/zeek/etc
COPY --from=build-env /opt/zeek/include /opt/zeek/include
COPY --from=build-env /opt/zeek/logs /opt/zeek/logs
COPY --from=build-env /opt/zeek/share /opt/zeek/share
COPY --from=build-env /opt/zeek/spool /opt/zeek/spool
COPY --from=build-env /opt/zeek/var /opt/zeek/var

WORKDIR /home/work
RUN mkdir /opt/ot_tools

#suricataバイナリファイルのコピー
#COPY --from=build-env /usr/bin/suricata /usr/bin/suricata
#COPY --from=build-env /usr/bin/suricata-update /usr/bin/suricata-update
#COPY --from=build-env /usr/bin/suricatactl /usr/bin/suricatactl
#COPY --from=build-env /usr/bin/suricatasc /usr/bin/suricatasc
#COPY --from=build-env /etc/suricata /etc/suricata
#COPY --from=build-env /var/log/suricata /var/log/suricata
#COPY --from=build-env /var/lib/suricata /var/lib/suricata

#COPY --from=build-env /usr/lib/python3.8/site-packages/suricata /usr/lib/python3.8/site-packages/suricata
#COPY --from=build-env /usr/share/doc/suricata /usr/share/doc/suricata
#COPY --from=build-env /usr/share/suricata /usr/share/suricata
#COPY --from=build-env /run/suricata /run/suricata
#COPY --from=build-env /home/work/suricata-6.0.4/libhtp/htp/.libs/libhtp.so.2.0.0 /lib

# Zeel、Suricata、Yafの資材配置。
WORKDIR /
COPY --from=build-env /home/work/ot_tools /home/work/ot_tools
COPY --from=build-env /home/work/ot_tools/broscript/conn/__load__.zeek /opt/zeek/share/zeek/base/protocols/conn/
COPY --from=build-env /home/work/ot_tools/broscript/conn/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/conn/
COPY --from=build-env /home/work/ot_tools/broscript/http/__load__.zeek /opt/zeek/share/zeek/base/protocols/http/
COPY --from=build-env /home/work/ot_tools/broscript/http/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/http/
COPY --from=build-env /home/work/ot_tools/broscript/arp.zeek /opt/zeek/share/zeek/site/arp.zeek
COPY --from=build-env /home/work/ot_tools/broscript/ns.zeek /opt/zeek/share/zeek/site/ns.zeek
COPY --from=build-env /home/work/ot_tools/broscript/main_bacnet.zeek /opt/zeek/share/zeek/site/main_bacnet.zeek
COPY --from=build-env /home/work/ot_tools/broscript/consts_bacnet.zeek /opt/zeek/share/zeek/site/consts_bacnet.zeek
COPY --from=build-env /home/work/ot_tools/*.sh /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/suricata.yaml /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/tsharkfields2bacnetservicelog_dict.awk /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/yaf.awk /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/p0f /home/work/ot_tools/

RUN cp -pr /home/work/ot_tools/p0f /opt/

WORKDIR /home/work

RUN apt purge -y python3-yaml

RUN python3.8 -m pip install --upgrade pip --no-cache-dir
RUN python3.8 -m pip install setuptools==59.8.0
RUN python3.8 -m pip install -r requirements.txt --no-cache-dir
RUN mkdir /var/log/ot_tools
#RUN pip install django

COPY --from=build-env /usr/local/bin/zkg  /usr/local/bin/zkg

ENV PATH $PATH:/opt/zeek/bin

# Yafバイナリファイルのコピー。
#COPY --from=build-env /usr/local/bin/yaf /usr/local/bin/yaf
#COPY --from=build-env /usr/local/bin/yafscii /usr/local/bin/yafscii
#RUN ldconfig

# Yafのインストール。バイナリファイルのコピーでは動作確認とれなかったため。
RUN wget https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz
RUN tar xvfJ glib-2.60.7.tar.xz
RUN cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig
RUN cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz
RUN cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install
RUN cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz
RUN cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig

# suricata
RUN add-apt-repository ppa:oisf/suricata-6.0
RUN apt-get update && apt-get install -y suricata

# suricata rules
RUN wget http://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz \
 && tar -xzvf emerging.rules.tar.gz \
 && mkdir -p /var/lib/suricata/rules \
 && rm rules/*ja3.rules \
 && grep -h -ve "^#" -ve "^$" rules/*.rules > /var/lib/suricata/rules/suricata.rules

# suricata
RUN add-apt-repository ppa:oisf/suricata-stable
RUN apt-get update && apt-get install -y suricata

# suricata rules
RUN wget http://rules.emergingthreats.net/open/suricata-6.0.4/emerging.rules.tar.gz \
 && tar -xzvf emerging.rules.tar.gz \
 && mkdir -p /var/lib/suricata/rules \
 && grep -h -ve "^#" -ve "^$" rules/*.rules > /var/lib/suricata/rules/suricata.rules

RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
    && mv supervisord.conf /etc/supervisor/conf.d/

RUN zkg autoconfig && zkg install --force --skiptest \
    zeek-plugin-bacnet \
    zeek-plugin-enip \
    zeek-plugin-profinet \
    zeek-plugin-s7comm \
    icsnpp-ethercat \
    icsnpp-opcua-binary \
    icsnpp-modbus