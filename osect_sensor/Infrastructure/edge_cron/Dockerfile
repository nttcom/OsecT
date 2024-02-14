FROM ubuntu:22.04 As build-env
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
    kmod \
    gawk \
    # git \
    libmount-dev \
    libpcre3-dev \
    libyaml-dev \
    libpcap0.8-dev \
    libjansson-dev \
    libpcap-dev \
    libssl-dev \
    libmaxminddb-dev \
    ninja-build \
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
    wget \
    zlib1g-dev \
    libpcre3 \
    libpcre3-dbg \
    libyaml-0-2 \
    zlib1g \
    libmagic-dev \
    software-properties-common \
    libfl-dev \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata

# pip関係のインストール
WORKDIR /home/work
RUN apt-get purge -y python3-yaml \
    && python3.10 -m pip install --upgrade pip --no-cache-dir \
    && python3.10 -m pip install setuptools==59.8.0 --no-cache-dir \
    && python3.10 -m pip install -r requirements.txt --no-cache-dir

WORKDIR /home/work
# Yafのインストール
RUN wget -q https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz \
 && tar xvfJ glib-2.60.7.tar.xz \
 && cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig \
 && cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz \
 && cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install \
 && cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz \
 && cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig

# suricata rules
RUN wget -q http://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz \
    && tar -xzvf emerging.rules.tar.gz \
    && mkdir -p /var/lib/suricata/rules \
    && rm rules/*ja3.rules \
    && grep -h -ve "^#" -ve "^$" rules/*.rules > /var/lib/suricata/rules/suricata.rules

# zeek-parser-Bacnetのclone
WORKDIR /home/work
RUN git clone https://github.com/nttcom/zeek-parser-Bacnet.git

# 本番イメージ
FROM zeek/zeek:5.0.0
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/work
COPY work/ /home/work
RUN mkdir /home/work/django && mkdir /home/work/uwsgi

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    cron \
    cargo \
    libpcap0.8-dev \
    libssl-dev \
    libmaxminddb-dev \
    python3-dev \
    python3-pip \
    python3-semantic-version \
    python3-git \
    supervisor \
    tzdata \
    wget \
    cmake \
    make \
    gcc \
    g++ \
    flex \
    libfl-dev \
    bison \
    libpcap-dev \
    build-essential \
    libpcap0.8-dev \
    software-properties-common \
    libpcre3 \
    libpcre3-dbg \
    libpcre3-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    pkg-config \
    zlib1g \
    zlib1g-dev \
    libcap-ng-dev \
    libcap-ng0 \
    libmagic-dev \
    libnss3-dev \
    libgeoip-dev \
    liblua5.1-dev \
    libhiredis-dev \
    libevent-dev \
    # python-yaml \
    rustc \
    autoconf \
    automake \
    libtool \
    libjansson-dev \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata
#  && cargo install --force cbindgen

# pip関係のインストール
WORKDIR /home/work
RUN apt-get update \
    && apt-get purge -y python3-yaml \
    && python3.9 -m pip install --upgrade pip --no-cache-dir \
    && python3.9 -m pip install setuptools==59.8.0 --no-cache-dir \
    && python3.9 -m pip install -r requirements.txt --no-cache-dir

ENV PATH $PATH:/root/.cargo/bin

# zkgパッケージ（必要なものだけ入れる）
ENV PATH $PATH:/usr/local/zeek/bin
# RUN zkg autoconfig
RUN zkg install icsnpp-modbus --version 03de54df8b0a8c1e6264876167f80dccae74902a --force --skiptest \
    && zkg refresh \
    && zkg install --force --skiptest \
#    zeek-plugin-bacnet \
#    zeek-plugin-enip \
#    zeek-plugin-profinet \
#    zeek-plugin-s7comm \
#    icsnpp-ethercat \
#    icsnpp-opcua-binary \
    icsnpp-modbus \
    icsnpp-bacnet \
    zeek/corelight/zeek-long-connections \
    zeek-af_packet-plugin \
    zeek-parser-CCLinkFieldBasic \
    zeek-parser-CCLinkIENoIP \
    zeek-parser-CCLinkTSNPTP \
    zeek-parser-CCLinkTSNSLMP \
    zeek-parser-CIFS-COM \
    zeek-parser-CIFS-NBNS-COM \
    zeek-parser-DHCPv4-COM \
    zeek-parser-DHCPv6-COM \
    zeek-parser-SSDP-COM

# Yafを含むバイナリファイルをコピー
RUN mkdir /var/log/yaf
COPY --from=build-env /usr/local/bin /usr/local/bin
COPY --from=build-env /usr/local/lib /usr/local/lib
# zeek-parser-Bacnetのコピー
COPY --from=build-env /home/work/zeek-parser-Bacnet /home/work/zeek-parser-Bacnet

# Suricataはほぼ無駄がないためそのままインストール
# Suricata rulesをコピー
RUN mkdir -p /var/lib/suricata/rules
COPY --from=build-env /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules

WORKDIR /home/work

# suricataのインストール
# suricata のバージョンアップに追随するためにリリース前には最新のバージョンであることを確認すること
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
RUN wget https://www.openinfosecfoundation.org/download/suricata-6.0.16.tar.gz \
    && tar -xvzf suricata-6.0.16.tar.gz \
    && cd suricata-6.0.16 \
    && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-gccmarch-native \
    && make \
    && make install \
    && make install-conf \
    && ldconfig

# Zeel、Suricata、Yafの資材配置。SaaS版ではコメントアウトすること。
WORKDIR /home/work
RUN mkdir /opt/ot_tools \
    && cp -p ot_tools/broscript/conn/__load__.zeek /usr/local/zeek/share/zeek/base/protocols/conn/ \
    && cp -p ot_tools/broscript/conn/mac-logging.zeek /usr/local/zeek/share/zeek/base/protocols/conn/ \
    && cp -p ot_tools/broscript/http/__load__.zeek /usr/local/zeek/share/zeek/base/protocols/http/ \
    && cp -p ot_tools/broscript/http/mac-logging.zeek /usr/local/zeek/share/zeek/base/protocols/http/ \
    && cp -p ot_tools/broscript/arp.zeek /usr/local/zeek/share/zeek/site \
    && cp -p ot_tools/broscript/ns.zeek /usr/local/zeek/share/zeek/site \
    && cp -p ot_tools/broscript/zeek_long_connections/main.zeek /usr/local/zeek/share/zeek/site/zeek-long-connections/ \
    && cp -p ot_tools/*.sh /opt/ot_tools/ \
    && cp -p ot_tools/yaf.awk /opt/ot_tools/ \
    && cp -pr ot_tools/p0f /opt/ \
    && cp -p zeek-parser-Bacnet/scripts/bacnet_ip.zeek /usr/local/zeek/share/zeek/site/icsnpp-bacnet/main.zeek \
    && cp -p zeek-parser-Bacnet/scripts/consts_bacnet_ip.zeek /usr/local/zeek/lib/zeek/plugins/packages/icsnpp-bacnet/scripts/consts.zeek

# 環境変数
RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
    && mv supervisord.conf /etc/supervisor/conf.d/
