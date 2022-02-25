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
    zlib1g-dev\
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
  && dpkg-reconfigure -f noninteractive tzdata

# Zeekのインストール。
RUN git clone --recursive https://github.com/zeek/zeek -b v4.0.5
#WORKDIR /home/work/zeek
RUN cd zeek && ./configure --prefix=/opt/zeek && make && make install
# && cd ~/ || exit && mkdir /opt/ot_tools
WORKDIR /
RUN mkdir /opt/ot_tools

#suricata
WORKDIR /home/work
RUN wget https://www.openinfosecfoundation.org/download/suricata-6.0.4.tar.gz \
 && tar -xf suricata-6.0.4.tar.gz 
#WORKDIR /home/work/suricata-6.0.4
RUN cd /home/work/suricata-6.0.4 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && make install-full 
WORKDIR /
RUN wget http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz \
 && tar -xzvf emerging.rules.tar.gz \
 && mkdir -p /var/lib/suricata \
 && cp -pr rules /var/lib/suricata/

# Zeel、Suricata、Yafの資材配置。SaaS版ではコメントアウトすること。
#RUN cp -p ot_tools/broscript/conn/__load__.zeek /opt/zeek/share/zeek/base/protocols/conn/
#RUN cp -p ot_tools/broscript/conn/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/conn/
#RUN cp -p ot_tools/broscript/http/__load__.zeek /opt/zeek/share/zeek/base/protocols/http/
#RUN cp -p ot_tools/broscript/http/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/http/
#RUN cp -p ot_tools/broscript/arp.zeek /opt/zeek/share/zeek/base/protocols/
#RUN cp -p ot_tools/broscript/ns.zeek /opt/zeek/share/zeek/base/protocols/
#RUN cp -p ot_tools/*.sh /opt/ot_tools/
#RUN cp -p ot_tools/suricata.yaml /opt/ot_tools/
#RUN cp -p ot_tools/tsharkfields2bacnetservicelog_dict.awk /opt/ot_tools/
#RUN cp -p ot_tools/yaf.awk /opt/ot_tools/
#RUN cp -pr ot_tools/p0f /opt/

WORKDIR /home/work
RUN apt purge -y python3-yaml

RUN python3.8 -m pip install --upgrade pip --no-cache-dir
RUN python3.8 -m pip install setuptools==59.8.0
RUN python3.8 -m pip install -r requirements.txt --no-cache-dir
RUN mkdir /var/log/ot_tools
ENV PATH $PATH:/opt/zeek/bin
RUN zkg autoconfig && zkg install --force zeek-plugin-bacnet

# Yafのインストール。
RUN wget https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz \
 && tar xvfJ glib-2.60.7.tar.xz \
 && cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig \
 && cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz \
 && cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install \
 && cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz \
 && cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig

#本番イメージ
FROM ubuntu:20.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
#    bison \
#    cmake \
    cron \
#    cargo \
#    build-essential \
#    flex \
    gawk \
#    gcc \
#    g++ \
#    libmount-dev \
#    libpcre3-dev \
#    libyaml-dev \
#    libpcap0.8-dev \
#    libjansson-dev \
#    libpcap-dev \
#    libssl-dev \
#    libmaxminddb-dev \
#    ninja-build \
#    make \
#    pkg-config \
#    python3-dev \
    python3-pip \
#    python3-yaml \
#    python3-semantic-version \
#    python3-git \
#    rustc \
    supervisor \
#    swig \
    tshark \
    tzdata \
#    vim \
#    wget \
#    zlib1g-dev\
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* \
 && echo "${TZ}" > /etc/timezone \
  && dpkg-reconfigure -f noninteractive tzdata

#zeekのバイナリファイルをコピー
COPY --from=build-env /opt/zeek/bin /opt/zeek/bin
COPY --from=build-env /opt/zeek/lib /opt/zeek/lib 
WORKDIR /home/work

# Suricataのインストール。
#RUN wget https://www.openinfosecfoundation.org/download/suricata-6.0.4.tar.gz \
# && tar -xf suricata-6.0.4.tar.gz \
# && cd /home/work/suricata-6.0.4 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && make install-full \
# && cd ~/ || exit \
# && wget http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz \
# && tar -xzvf emerging.rules.tar.gz \
# && mkdir -p /var/lib/suricata \
# && cp -pr rules /var/lib/suricata/

#suricataバイナリファイルのコピー
COPY --from=build-env /usr/bin/suricata /usr/bin/suricata

#RUN mkdir -p /var/lib/suricata
#COPY --from=build-env /home/work/suricata-6.0.4 /var/lib/suricata

# Zeel、Suricata、Yafの資材配置。
COPY --from=build-env /home/work/ot_tools /home/work/ot_tools
COPY --from=build-env /home/work/ot_tools/broscript/conn/__load__.zeek /opt/zeek/share/zeek/base/protocols/conn/
COPY --from=build-env /home/work/ot_tools/broscript/conn/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/conn/
COPY --from=build-env /home/work/ot_tools/broscript/http/__load__.zeek /opt/zeek/share/zeek/base/protocols/http/
COPY --from=build-env /home/work/ot_tools/broscript/http/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/http/
COPY --from=build-env /home/work/ot_tools/broscript/arp.zeek /opt/zeek/share/zeek/base/protocols/
COPY --from=build-env /home/work/ot_tools/broscript/ns.zeek /opt/zeek/share/zeek/base/protocols/
COPY --from=build-env /home/work/ot_tools/broscript/main_bacnet.zeek /opt/zeek/share/zeek/base/protocols/
COPY --from=build-env /home/work/ot_tools/broscript/consts_bacnet.zeek /opt/zeek/share/zeek/base/protocols/
COPY --from=build-env /home/work/ot_tools/*.sh /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/suricata.yaml /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/tsharkfields2bacnetservicelog_dict.awk /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/yaf.awk /opt/ot_tools/
COPY --from=build-env /home/work/ot_tools/p0f /opt/

#RUN cp -p ot_tools/broscript/conn/__load__.zeek /opt/zeek/share/zeek/base/protocols/conn/ \
# && cp -p ot_tools/broscript/aaconn/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/conn/ \
# && cp -p ot_tools/broscript/http/__load__.zeek /opt/zeek/share/zeek/base/protocols/http/ \
# && cp -p ot_tools/broscript/http/mac-logging.zeek /opt/zeek/share/zeek/base/protocols/http/ \
# && cp -p ot_tools/broscript/arp.zeek /opt/zeek/share/zeek/base/protocols/ \
# && cp -p ot_tools/broscript/ns.zeek /opt/zeek/share/zeek/base/protocols/ \
# && cp -p ot_tools/*.sh /opt/ot_tools/ \
# && cp -p ot_tools/suricata.yaml /opt/ot_tools/ \
# && cp -p ot_tools/tsharkfields2bacnetservicelog_dict.awk /opt/ot_tools/ \
# && cp -p ot_tools/yaf.awk /opt/ot_tools/ \
# && cp -pr ot_tools/p0f /opt/ \


#ビルド用イメージからコピー。
COPY work/ /home/work
#COPY --from=build-env /home/work/requirements.txt /home/work/requirements.txt
#COPY --from=build-env /home/work/supervisord.conf /home/work/supervisord.conf
#COPY --from=build-env /home/work/crontab /home/work/crontab


#RUN apt purge -y python3-yaml \
RUN python3.8 -m pip install --upgrade pip --no-cache-dir \
 && python3.8 -m pip install setuptools==59.8.0 \
 && python3.8 -m pip install -r requirements.txt --no-cache-dir \
 && mkdir /var/log/ot_tools

RUN pip install django

# Yafのインストール。
#RUN wget https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz \
# && tar xvfJ glib-2.60.7.tar.xz \
# && cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig \
# && cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz \
# && cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install \
# && cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz \
# && cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig 
#Yafバイナリファイルのコピー。
COPY --from=build-env /usr/local/bin/yaf /usr/local/bin/yaf
#COPY --from=build-env /usr/local/bin/yafMeta2Pcap /usr/local/bin/yafMeta2Pcap
#COPY --from=build-env /usr/local/bin/yafcollect /usr/local/bin/yafcollect
COPY --from=build-env /usr/local/bin/yafscii /usr/local/bin/yafscii

RUN mv crontab /root/crontab \
 && crontab /root/crontab \
 && printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt \
 && mv supervisord.conf /etc/supervisor/conf.d/
