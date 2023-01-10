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
    kmod \
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

# Zeekのインストール
RUN git clone --recursive https://github.com/zeek/zeek -b v5.0.0
WORKDIR /home/work/zeek
RUN ./configure --build-type=Release --prefix=/opt/zeek \
 && make \
 && make install
ENV PATH $PATH:/opt/zeek/bin

# Spicyのインストール
RUN wget -q https://github.com/zeek/spicy/releases/download/v1.5.1/spicy_linux_ubuntu20.deb \
  && dpkg --install spicy_linux_ubuntu20.deb
ENV PATH $PATH:/opt/spicy/bin

# pip関係のインストール
WORKDIR /home/work
RUN apt-get purge -y python3-yaml \
    && python3.8 -m pip install --upgrade pip --no-cache-dir \
    && python3.8 -m pip install setuptools==59.8.0 --no-cache-dir \
    && python3.8 -m pip install -r requirements.txt --no-cache-dir

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

# zkgパッケージ（必要なものだけ入れる）
ENV PATH $PATH:/opt/zeek/bin
# RUN zkg autoconfig
RUN zkg install --force --skiptest \
#    zeek-plugin-bacnet \
#    zeek-plugin-enip \
#    zeek-plugin-profinet \
#    zeek-plugin-s7comm \
#    icsnpp-ethercat \
#    icsnpp-opcua-binary \
#    icsnpp-modbus \
    zeek/corelight/zeek-long-connections \
    zeek-af_packet-plugin

# spicyのコンパイル
WORKDIR /home/work/ot_tools/broscript/CIFS_B/
RUN spicyz -o CIFS_B.hlto CIFS_B.spicy CIFS_B.evt

WORKDIR /home/work/ot_tools/broscript/MYDHCP/
RUN spicyz -o MYDHCP.hlto MYDHCP.spicy zeek_MYDHCP.spicy MYDHCP.evt

WORKDIR /home/work/ot_tools/broscript/DHCPV6/
RUN spicyz -o dhcpv6.hlto dhcpv6.spicy zeek_dhcpv6.spicy dhcpv6.evt

WORKDIR /home/work/ot_tools/broscript/NBNS/
RUN spicyz -o nbns.hlto nbns.spicy nbns.evt

WORKDIR /home/work/ot_tools/broscript/SSDP/
RUN spicyz -o ssdp.hlto ssdp.spicy ssdp.evt

WORKDIR /home/work/ot_tools/broscript/CC_LINK_BASIC/
RUN spicyz -o cc_link_basic.hlto cc_link_basic.spicy cc_link_basic.evt

WORKDIR /home/work/ot_tools/broscript/CC_LINK_NOIP/
RUN spicyz -o cc_link_noip.hlto cc_link_noip.spicy cc_link_noip.evt

WORKDIR /home/work
RUN cp -p ot_tools/broscript/CIFS_B/CIFS_B.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/CIFS_B/CIFS_B.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/MYDHCP/MYDHCP.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/MYDHCP/MYDHCP.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/DHCPV6/dhcpv6.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/DHCPV6/dhcpv6.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/NBNS/nbns.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/NBNS/nbns.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/SSDP/ssdp.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/SSDP/ssdp.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/CC_LINK_BASIC/cc_link_basic.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/CC_LINK_BASIC/cc_link_basic.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/CC_LINK_NOIP/cc_link_noip.hlto /opt/zeek/lib/zeek-spicy/modules/ \
    && cp -p ot_tools/broscript/CC_LINK_NOIP/cc_link_noip.zeek /opt/zeek/share/zeek/site/

# 本番イメージ
FROM ubuntu:20.04
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
    software-properties-common \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata \
 && cargo install --force cbindgen

ENV PATH $PATH:/root/.cargo/bin

# Zeekのバイナリファイルをコピー
COPY --from=build-env /opt/zeek /opt/zeek
WORKDIR /
ENV PATH $PATH:/opt/zeek/bin

# Yafを含むバイナリファイルをコピー
RUN mkdir /var/log/yaf
COPY --from=build-env /usr/local/bin /usr/local/bin
COPY --from=build-env /usr/local/lib /usr/local/lib

# Suricataはほぼ無駄がないためそのままインストール
# Suricata rulesをコピー
RUN mkdir -p /var/lib/suricata/rules
COPY --from=build-env /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules

WORKDIR /home/work

# suricataのインストール（eBPFなし）
RUN add-apt-repository ppa:oisf/suricata-6.0 \
    &&  apt-get update \
    && 	apt-get install -y --no-install-recommends suricata \
    && 	apt-get --purge remove -y software-properties-common \
    && 	apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*

# Zeel、Suricata、Yafの資材配置。SaaS版ではコメントアウトすること。
WORKDIR /home/work
RUN mkdir /opt/ot_tools \
    && cp -p ot_tools/broscript/conn/__load__.zeek /opt/zeek/share/zeek/base/protocols/conn/ \
    && cp -p ot_tools/broscript/conn/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/conn/ \
    && cp -p ot_tools/broscript/http/__load__.zeek /opt/zeek/share/zeek/base/protocols/http/ \
    && cp -p ot_tools/broscript/http/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/http/ \
    && cp -p ot_tools/broscript/arp.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/ns.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/main_bacnet.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/broscript/consts_bacnet.zeek /opt/zeek/share/zeek/site/ \
    && cp -p ot_tools/*.sh /opt/ot_tools/ \
    && cp -p ot_tools/tsharkfields2bacnetservicelog_dict.awk /opt/ot_tools/ \
    && cp -p ot_tools/yaf.awk /opt/ot_tools/ \
    && cp -pr ot_tools/p0f /opt/

# 環境変数
RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
    && mv supervisord.conf /etc/supervisor/conf.d/

