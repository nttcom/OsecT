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
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata

# Zeekのインストール。
RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
RUN cd zeek \
  && ./configure --build-type=Release --prefix=/opt/zeek \
  && make \
  && make install

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

# suricataのインストール（eBPFなし）
#RUN add-apt-repository ppa:oisf/suricata-6.0 \
#    &&  apt-get update \
#    && 	apt-get install -y --no-install-recommends suricata \
#    && 	apt-get -y clean \
#    && rm -rf /var/lib/apt/lists/*

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
    # pypy3 \
    # pypy3-dev \
    python3-dev \
    python3-pip \
    python3-semantic-version \
    python3-git \
    supervisor \
    tzdata \
    wget \
    logrotate \
    tcpreplay \
    iproute2 \
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
COPY --from=build-env /usr/local/bin /usr/local/bin
COPY --from=build-env /usr/local/lib /usr/local/lib
RUN mkdir /var/log/yaf

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

# get-pip.py
#RUN wget -q https://bootstrap.pypa.io/pip/3.6/get-pip.py \
#  && pypy3 get-pip.py

# pypy3で実行する場合
#RUN pypy3 -m pip install --upgrade pip --no-cache-dir \
#    && pypy3 -m pip install setuptools --no-cache-dir \
#    && pypy3 -m pip install -r requirements.txt --no-cache-dir \
#    && mkdir /var/log/ot_tools

RUN python3.8 -m pip install --upgrade pip --no-cache-dir \
    && python3.8 -m pip install setuptools --no-cache-dir \
    && python3.8 -m pip install -r requirements.txt --no-cache-dir \
    && mkdir /var/log/ot_tools

WORKDIR /home/work
# Zeel、Suricata、Yafの資材配置。SaaS版ではコメントアウトすること。
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

RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
    && mv supervisord.conf /etc/supervisor/conf.d/
