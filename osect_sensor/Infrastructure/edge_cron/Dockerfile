FROM ubuntu:18.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /home/work
RUN mkdir /home/work/django
RUN mkdir /home/work/uwsgi
COPY work/ /home/work
WORKDIR /home/work

RUN apt update \
 && apt install -y --no-install-recommends \
    cron \
    cargo \
    build-essential \
#    gnupg \
    gawk \
#    git \
#    gperf \
#    libsystemd-dev \
#    libffi-dev \
    libmount-dev \
    libpcre3-dev \
    libyaml-dev \
    libpcap0.8-dev \
    libjansson-dev \
#    libpq-dev \
#    libcap-ng-dev \
#    libnspr4-dev \
#    libnss3-dev \
#    libmagic-dev \
#    liblz4-dev \
    ninja-build \
#    python3.7-dev \
    pkg-config \
    python3.7 \
    python3-pip \
    python3-setuptools \
    python3-yaml \
    rustc \
#    sqlite3 \
    supervisor \
    tshark \
    tzdata \
    vim \
    wget \
    zlib1g-dev\
    libpcap-dev \
    libssl-dev \
    libmaxminddb-dev \
    python3-semantic-version \
    python3-git \
#    python3-gitdb \
#    python3-smmap \
 && apt -y clean \
 && rm -rf /var/lib/apt/lists/*

RUN echo "${TZ}" > /etc/timezone \
   && dpkg-reconfigure -f noninteractive tzdata

RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/libbroker-dev_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeek-btest_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeek-core-dev_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeek-core_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeek-libcaf-dev_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeek-zkg_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeek_4.0.3-0_amd64.deb
RUN wget -P ./ot_tools/bro/ https://provo-mirror.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/amd64/zeekctl_4.0.3-0_amd64.deb

RUN apt install ./ot_tools/bro/zeek-core_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/zeek-btest_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/zeekctl_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/libbroker-dev_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/zeek-libcaf-dev_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/zeek-core-dev_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/zeek-zkg_4.0.3-0_amd64.deb
RUN apt install ./ot_tools/bro/zeek_4.0.3-0_amd64.deb

RUN mkdir /opt/ot_tools

RUN wget https://www.openinfosecfoundation.org/download/suricata-6.0.2.tar.gz
RUN tar -xf suricata-6.0.2.tar.gz
RUN cd /home/work/suricata-6.0.2 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && make install-full
RUN cd ~/
RUN wget http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz
RUN tar -xzvf emerging.rules.tar.gz
RUN mkdir -p /var/lib/suricata
RUN cp -pr rules /var/lib/suricata/

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

RUN python3.7 -m pip install --upgrade pip
RUN python3.7 -m pip install -r requirements.txt
RUN mkdir /var/log/ot_tools

# Installation of yaf dependent packages
# meson install
RUN wget https://github.com/mesonbuild/meson/releases/download/0.56.0/meson-0.56.0.tar.gz
RUN tar xvfz meson-0.56.0.tar.gz
RUN cd /home/work/meson-0.56.0/ && python3.7 setup.py install
# glib install
RUN wget https://download.gnome.org/sources/glib/2.60/glib-2.60.7.tar.xz
RUN tar xvfJ glib-2.60.7.tar.xz
RUN cd /home/work/glib-2.60.7/ && meson _build && ninja -C _build install && ldconfig
# libfixbuf install
RUN cd /home/work/ot_tools/ && tar xvzf libfixbuf-2.4.0.tar.gz
RUN cd /home/work/ot_tools/libfixbuf-2.4.0/ && ./configure && make && make install
# yaf install
RUN cd /home/work/ot_tools/ && tar xvzf yaf-2.11.0.tar.gz
RUN cd /home/work/ot_tools/yaf-2.11.0/ && ./configure && make && make install && ldconfig


RUN mv crontab /root/crontab
RUN crontab /root/crontab

RUN printenv | grep -e https_proxy -e HTTPS_PROXY -e http_proxy -e HTTP_PROXY -e no_proxy -e NO_PROXY| awk '{print "export " $1}' > /opt/ot_tools/proxy_env.txt

RUN mv supervisord.conf /etc/supervisor/conf.d/

# CMD ["/usr/bin/supervisord","--configuration=/etc/supervisor/conf.d/supervisord.conf"]
