FROM ubuntu:18.04
ENV LANG C.UTF-8
ENV TZ Asia/Tokyo
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /home/work
# RUN mkdir /home/work/django
# RUN mkdir /home/work/uwsgi
COPY work/ /home/work
WORKDIR /home/work

RUN apt update \
 && apt install -y --no-install-recommends \
#    build-essential \
#    net-tools \
#    libpq-dev \
    python3.7 \
#    python3.7-dev \
    python3-pip \
#    python3-setuptools \
#    sqlite3 \
#    supervisor \
    tcpdump \
    tzdata \
    vim \
 && apt -y clean \
 && rm -rf /var/lib/apt/lists/*

RUN echo "${TZ}" > /etc/timezone \
   && dpkg-reconfigure -f noninteractive tzdata

RUN mkdir /opt/ot_tools

RUN cp -p ot_tools/*.sh /opt/ot_tools/

RUN python3.7 -m pip install --upgrade pip
RUN python3.7 -m pip install -r requirements.txt

# RUN mv supervisord.conf /etc/supervisor/conf.d/
WORKDIR /opt/edge_tcpdump

# CMD ["/usr/bin/supervisord","--configuration=/etc/supervisor/conf.d/supervisord.conf"]
