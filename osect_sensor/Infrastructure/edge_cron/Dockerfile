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

# Zeekのインストール
RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
RUN cd zeek \
 && ./configure --build-type=Release --prefix=/opt/zeek \
 && make \
 && make install

# Zeekのインストール（PF_RINGあり）
#RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
#RUN cd zeek \
#    && ./configure --build-type=Release --prefix=/opt/zeek --with-pcap=/opt/pfring \
#    && make \
#    && make install

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
RUN zkg autoconfig && zkg install --force --skiptest \
    zeek-plugin-bacnet \
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
#    bison \
#    cmake \
    cron \
    cargo \
#    build-essential \
#    flex \
#    gawk \
#    gcc \
#    g++ \
#    libmount-dev \
#    libpcre3-dev \
#    libyaml-dev \
    libpcap0.8-dev \
#    libjansson-dev \
#    libpcap-dev \
    libssl-dev \
    libmaxminddb-dev \
#    ninja-build \
#    make \
#    pkg-config \
    python3-dev \
    python3-pip \
#    python3-yaml \
    python3-semantic-version \
#    python3-setuptools \
    python3-git \
#    rustc \
    supervisor \
#    swig \
    tzdata \
    wget \
#    zlib1g-dev \
#    libpcre3 \
#    libpcre3-dbg \
#    libyaml-0-2 \
#    zlib1g \
    software-properties-common \
#    libmagic-dev \
#    linux-headers-$(uname -r) \
#    kmod \
#    zlib1g-dev \
#    dh-autoreconf \
#    llvm \
#    libcap-ng-dev \
#    libunwind-dev \
    logrotate \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
 && dpkg-reconfigure -f noninteractive tzdata \
 && cargo install --force cbindgen

ENV PATH $PATH:/root/.cargo/bin

# PF_RINGのインストール
#WORKDIR /usr/src
#RUN git clone https://github.com/ntop/PF_RING.git
#WORKDIR /usr/src/PF_RING/userland/lib
#RUN ./configure --prefix=/opt/pfring && make install
#WORKDIR /usr/src/PF_RING/userland/libpcap
#RUN ./configure --prefix=/opt/pfring && make install
#WORKDIR /usr/src/PF_RING/userland/tcpdump
#RUN ./configure --prefix=/opt/pfring && make install
#WORKDIR /usr/src/PF_RING/kernel
#RUN make && make install
# RUN modprobe pf_ring enable_tx_capture=0 min_num_slots=32768

# Zeekのバイナリファイルをコピー
COPY --from=build-env /opt/zeek /opt/zeek
WORKDIR /
ENV PATH $PATH:/opt/zeek/bin

# Yafを含むバイナリファイルをコピー
COPY --from=build-env /usr/local/bin /usr/local/bin
COPY --from=build-env /usr/local/lib /usr/local/lib
RUN mkdir /var/log/yaf

# Suricataはほぼ無駄がないためそのままインストール
# Suricata rulesをコピー
RUN mkdir -p /var/lib/suricata/rules
COPY --from=build-env /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules

# Zeekのインストール（PF_RINGあり）
#RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
#RUN cd zeek && ./configure --prefix=/opt/zeek --with-pcap=/opt/pfring && make && make install
#WORKDIR /
#RUN mkdir /opt/ot_tools
#ENV PATH $PATH:/opt/zeek/bin

# Zeekのインストール（PF_RINGなし）
#RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
#RUN cd zeek && ./configure --prefix=/opt/zeek && make && make install
#WORKDIR /
#RUN mkdir /opt/ot_tools
#ENV PATH $PATH:/opt/zeek/bin

# これが発生するためやむなしでインストール
# ModuleNotFoundError: No module named 'zeekpkg'
#WORKDIR /home/work
#RUN apt-get purge -y python3-yaml \
#&&  python3.8 -m pip install --upgrade pip --no-cache-dir \
#    && python3.8 -m pip install setuptools==59.8.0 --no-cache-dir \
#    && python3.8 -m pip install -r requirements.txt --no-cache-dir \
#    && mkdir /var/log/ot_tools

WORKDIR /home/work
# Yafのインストール
#RUN wget -q https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz \
# && tar xvfJ glib-2.60.7.tar.xz \
# && cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig \
# && cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz \
# && cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install \
# && cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz \
# && cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig

# suricataのインストール（eBPFなし）
RUN add-apt-repository ppa:oisf/suricata-6.0 \
    &&  apt-get update \
    && 	apt-get install -y --no-install-recommends suricata \
    && 	apt-get --purge remove -y software-properties-common \
    && 	apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*

# suricataのインストール（eBPFあり）
#RUN git clone https://github.com/libbpf/libbpf.git \
#    && cd libbpf/src/ \
#    && echo "/usr/lib64" >> /etc/ld.so.conf.d/suricata.conf \
#    && make && make install \
#    && make install_headers \
#    && ldconfig
#RUN git clone https://github.com/OISF/suricata.git \
#    && cd suricata && git clone https://github.com/OISF/libhtp.git -b 0.5.x \
#    && ./autogen.sh \
#    && CC=clang ./configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ --enable-ebpf --enable-ebpf-build \
#    && make clean && make \
#    && make install-full \
#    && ldconfig \
#    && mkdir -p /usr/libexec/suricata/ebpf/ \
#    && cp ebpf/vlan_filter.bpf /usr/libexec/suricata/ebpf/ \
#    && cp ebpf/bypass_filter.bpf /usr/libexec/suricata/ebpf/

# suricata rules
#RUN wget -q http://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz \
#    && tar -xzvf emerging.rules.tar.gz \
#    && mkdir -p /var/lib/suricata/rules \
#    && rm rules/*ja3.rules \
#    && grep -h -ve "^#" -ve "^$" rules/*.rules > /var/lib/suricata/rules/suricata.rules

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

# 環境変数
RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
    && mv supervisord.conf /etc/supervisor/conf.d/

# zkgパッケージ（必要なものだけ入れる）
#RUN zkg autoconfig && zkg install --force --skiptest \
#    zeek-plugin-bacnet \
#    zeek-plugin-enip \
#    zeek-plugin-profinet \
#    zeek-plugin-s7comm \
#    icsnpp-ethercat \
#    icsnpp-opcua-binary \
#    icsnpp-modbus \
#    zeek/corelight/zeek-long-connections
