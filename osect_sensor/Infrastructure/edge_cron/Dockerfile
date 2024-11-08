FROM debian:bookworm-slim AS build-env
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/work
COPY work/ /home/work
RUN mkdir /home/work/django && mkdir /home/work/uwsgi
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    # yaf関連インストールにbison, meson, libmount-dev, python3-dev, python3-pipは必要
    autoconf \
    automake \
    bison \
    build-essential \
    cargo \
    cbindgen \
    gcc \
    git \
    g++ \
    libjansson-dev \
    libmount-dev \
    libpcap-dev \
    libpcre2-dev \
    libtool \
    libyaml-dev \
    make \
    meson \
    ninja-build \
    pkg-config \
    python3-dev \
    python3-pip \
    python3-yaml \
    rustc \
    tzdata \
    wget \
    zlib1g-dev \
#    libcap-ng-dev \
#    libevent-dev \
#    libgeoip-dev \
#    libhiredis-dev \
#    liblua5.1-dev \
#    libmagic-dev \
#    libmaxminddb-dev \
#    libnet-dev \
#    libnss3-dev \
#    libpcre3-dev \
#    flex \
#    libfl-dev \
#    libssl-dev \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata

WORKDIR /home/work
# Yafのインストール
RUN wget -q https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz \
 && tar xvfJ glib-2.60.7.tar.xz \
 && cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig \
 && cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz \
 && cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install \
 && cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz \
 && cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig

WORKDIR /home/work
# suricataのインストール
# suricata のバージョンアップに追随するためにリリース前には最新のバージョンであることを確認すること
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
RUN wget https://www.openinfosecfoundation.org/download/suricata-7.0.7.tar.gz \
    && tar -xvzf suricata-7.0.7.tar.gz \
    && cd suricata-7.0.7 \
    && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-gccmarch-native \
    && make \
    && make install \
    && make install-conf \
    && ldconfig

# zeek-parser-Bacnetのclone
# WORKDIR /home/work
# RUN git clone https://github.com/nttcom/zeek-parser-Bacnet.git

# 本番イメージ
FROM zeek/zeek:7.0.0
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/work
COPY work/ /home/work
RUN mkdir /home/work/django && mkdir /home/work/uwsgi

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    # cmake, build-essential, libpcap-devはzeek-parserインストールに必須
    # libyaml-dev, libmagic-dev, libpcre3-dev, libnet-dev, libnss3-devはsuricata実行に必須?
    build-essential \
    cmake \
    cron \
    gcc \
    libssl-dev \
#    libnet-dev \
#    libnss3-dev \
#    libmagic-dev \
    libpcap-dev \
#    libpcre3-dev \
    libyaml-dev \
    python3-dev \
    python3-pip \
    python3-semantic-version \
    python3-git \
    python3-yaml \
    supervisor \
    tzdata \
    wget \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* \
    && echo "${TZ}" > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata

# pip関係のインストール
WORKDIR /home/work
RUN apt-get update \
    && python3.11 -m pip install --upgrade pip --no-cache-dir --break-system-packages \
    && python3.11 -m pip install setuptools==59.8.0 --no-cache-dir --break-system-packages \
    && python3.11 -m pip install -r requirements.txt --no-cache-dir --break-system-packages

#ENV PATH $PATH:/root/.cargo/bin

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
#    icsnpp-bacnet \
    zeek/corelight/zeek-long-connections \
#    zeek-af_packet-plugin \
    zeek-parser-CCLinkFieldBasic \
    zeek-parser-CCLinkTSNSLMP \
    zeek-parser-CIFS-NBNS-COM \
    zeek-parser-DHCPv6-COM \
    zeek-parser-SSDP-COM \
    && zkg install zeek-parser-CIFS-COM --version 5e67a7a324075fe25a85cc3a4e1414cbef64ebe3 --force --skiptest \
    && zkg install zeek-parser-CCLinkTSNPTP --version 5c5c1264763b1dde2e0f7f057e50fe44524f4d84 --force --skiptest \
    && zkg install zeek-parser-CCLinkIENoIP --version 160ef68b489cc37545ad5ce90fbb6ea7ae204061 --force --skiptest \
    && zkg install zeek-parser-DHCPv4-COM --version 87004bbf8649089fa7d0dc0c153882d94c657dff --force --skiptest

# Yafを含むバイナリファイルをコピー
COPY --from=build-env /usr/local/bin /usr/local/bin
COPY --from=build-env /usr/local/lib /usr/local/lib
COPY --from=build-env /etc/suricata /etc/suricata
COPY --from=build-env /bin/suricata* /bin/
COPY --from=build-env /var/lib/suricata /var/lib/suricata
COPY --from=build-env /usr/lib/suricata /usr/lib/suricata
COPY --from=build-env /usr/share/suricata /usr/share/suricata
COPY --from=build-env /lib/libhtp.so.2 /lib/
RUN mkdir -p /var/log/yaf && mkdir -p /var/log/suricata && mkdir -p /var/lib/suricata/rules && ldconfig

# zeek-parser-Bacnetのコピー
# COPY --from=build-env /home/work/zeek-parser-Bacnet /home/work/zeek-parser-Bacnet

# Zeek、Suricata、Yafの資材配置。SaaS版ではコメントアウトすること。
WORKDIR /home/work
RUN mkdir /opt/ot_tools \
    && cp -p ot_tools/broscript/conn/__load__.zeek /usr/local/zeek/share/zeek/base/protocols/conn/ \
    && cp -p ot_tools/broscript/conn/mac-logging.zeek /usr/local/zeek/share/zeek/base/protocols/conn/ \
    && cp -p ot_tools/broscript/http/__load__.zeek /usr/local/zeek/share/zeek/base/protocols/http/ \
    && cp -p ot_tools/broscript/http/mac-logging.zeek /usr/local/zeek/share/zeek/base/protocols/http/ \
    && cp -p ot_tools/broscript/arp.zeek /usr/local/zeek/share/zeek/site \
    && cp -p ot_tools/broscript/ns.zeek /usr/local/zeek/share/zeek/site \
    && cp -p ot_tools/broscript/zeek_long_connections/main.zeek /usr/local/zeek/share/zeek/site/zeek-long-connections/ \
    && cp -p ot_tools/broscript/dns.zeek /usr/local/zeek/share/zeek/base/protocols/dns/main.zeek \
    # && cp -p zeek-parser-Bacnet/scripts/bacnet_ip.zeek /usr/local/zeek/share/zeek/site/icsnpp-bacnet/main.zeek \
    # && cp -p zeek-parser-Bacnet/scripts/consts_bacnet_ip.zeek /usr/local/zeek/lib/zeek/plugins/packages/icsnpp-bacnet/scripts/consts.zeek \
    && cp -p ot_tools/*.sh /opt/ot_tools/ \
    && cp -p ot_tools/yaf.awk /opt/ot_tools/ \
    && cp -pr ot_tools/p0f /opt/

# 環境変数
RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
    && mv supervisord.conf /etc/supervisor/conf.d/
