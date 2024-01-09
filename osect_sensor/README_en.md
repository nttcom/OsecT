# OsecT Sensor Installation Manual

## 0. Premise

Operations have been confirmed for the OS below:

- Ubuntu 18.04.5 LTS
- Ubuntu 20.04.5 LTS

In this manual, it is assumed to be installed directly under the directory (`~/osect_sensor`). If you want to install in a different directory, please change the path.

## 1. OS Update & Tool Installation

### 1.1 OS Update

Update the OS to the latest.

```bash
$ sudo apt update
$ sudo apt upgrade -y
```

### 1.2 Git Installation

Git is required to be downloaded.

```bash
$ sudo apt install -y git
```

### 1.3. Docker Installation

Set up a Docker repository.

```bash
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo apt-key fingerprint 0EBFCD88
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
```

Docker CE Installation

```bash
$ sudo apt install -y docker-ce
$ sudo usermod -aG docker <username>
$ docker container run --rm hello-world
```

Docker Compose 1.27.4 Installation

```bash
$ sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
```

### 1.4. Sosreport Installation

Sosreport is required to collect support logs for OsecT sensors.

```bash
$ sudo apt install -y sosreport
```

## 2. Installation Materials Download

Please download the installation materials from GitHub and place them directly under your home directory (~/).

```bash
$ cd ~
$ git clone https://github.com/nttcom/OsecT/

$ ls ~/OsecT/osect_sensor
Application  docker-compose.yml  Infrastructure  logs  tools
#Please make sure these files are shown.

$ mv ~/OsecT/osect_sensor ~/
```

## 3. OsecT Sensor Settings

### 3.1. Configuration of Monitoring Network Interface

Firstly, Please check the interface.
```bash
ip a
```

3 settings need to be configured.

1: Edit the crontab and specify the monitoring network.

```bash
$ vi ~/osect_sensor/conf/crontab
```

Part to edit:

```bash
* * * * * /opt/ot_tools/suricata_cron.sh enp1s0 > /dev/null 2>&1
* * * * * /opt/ot_tools/p0f_cron.sh enp1s0 > /dev/null 2>&1
* * * * * /opt/ot_tools/yaf_cron.sh enp1s0 > /dev/null 2>&1
```

Edited Example (when the monitoring network interface is enp0s8)

```bash
* * * * * /opt/ot_tools/suricata_cron.sh enp0s8 > /dev/null 2>&1
* * * * * /opt/ot_tools/p0f_cron.sh enp0s8 > /dev/null 2>&1
* * * * * /opt/ot_tools/yaf_cron.sh enp0s8 > /dev/null 2>&1
```

2: Edit suricata.yaml and specify the monitoring network.

```bash
$ vi ~/osect_sensor/conf/suricata.yaml
```

Part to edit:

```bash
# Linux high speed capture support
af-packet:
  - interface: eth1
```

Edited Example (when the monitoring network interface is enp0s8)

```bash
# Linux high speed capture support
af-packet:
  - interface: enp0s8
```

3: Edit node.cfg and specify the monitoring network.

```bash
$ vi ~/osect_sensor/conf/node.cfg
```

Part to edit:

```bash
[worker-1]
type=worker
host=localhost
interface=af_packet::eth1
lb_method=custom
lb_procs=6
pin_cpus=0,1,2,3,4,5
```

Edited Example (when the monitoring network interface is enp0s8)

```bash
[worker-1]
type=worker
host=localhost
interface=af_packet::enp0s8
lb_method=custom
lb_procs=6
pin_cpus=0,1,2,3,4,5
```

### 3.2. SECRET_KEY Configuration in Django

Set Django's SECRET_KEY.

```bash
$ SK=`cat /dev/urandom | base64 | fold -w 64 | head -n 1`; sed -i -e 's@SECRET_KEY = ""@SECRET_KEY = "'$SK'"@g' ~/osect_sensor/Application/edge_cron/edge_cron/settings.py
(Nothing is displayed.)
```

### 3.3. URL Configuration for Data Transmission

Please edit the data transmission URL provided by NTT Com in the configuration file.

```bash
$ vi Application/edge_cron/common/common_config.py
```

Part to edit:

```python
API_URL = 'https://your url/paper/api/v1/createlogdata/post'
```

Edited Example

```python
API_URL = 'https://xxxxx.osect.ntt.com/paper/api/v1/createlogdata/post'
```

### 3.4. Client Certificate Configuration

Store the client certificate provided by NTT Com to the path below (not need to change the file name).

```bash
$ ~/osect_sensor/keys/client.pem
```

## 4. Building and starting the container

```bash
$ cd ~/osect_sensor/
$ /usr/local/bin/docker-compose build
$ /usr/local/bin/docker-compose up -d
```
