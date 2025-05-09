# OsecTセンサーのインストール手順

English is [here](README_en.md)

## 0. 前提

動作確認済の機種は以下の通りです。

- [OKI AIエッジコンピューター「AE2100」](https://www.oki.com/jp/AIedge/)

また、Ubuntu 18.04.5 LTSおよびUbuntu 20.04.5 LTSで動作確認済みです。

本手順書では、ホームディレクトリ直下（`~/osect_sensor`）にインストールすることとしています。別のディレクトリにインストールする場合、パスを読み替えてください。

## 1. OSの更新及びツールのインストール

### 1.1 OSの更新

OSを最新の状態に更新します。

```bash
$ sudo apt update
$ sudo apt upgrade -y
```

### 1.2 Gitのインストール

インストール資材のダウンロードに必要なGitをインストールします。

```bash
$ sudo apt install -y git
```

### 1.3. Dockerのインストール

Dockerリポジトリを設定します。

```bash
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo apt-key fingerprint 0EBFCD88
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
```

Docker CEをインストールします。

```bash
$ sudo apt install -y docker-ce
$ sudo usermod -aG docker <username>
$ docker container run --rm hello-world
```

docker-compose 1.27.4をインストールします。

```bash
$ sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
```

### 1.4. sosreportのインストール

OsecTセンサーのサポートログの収集に必要なsosreportをインストールします。

```bash
$ sudo apt install -y sosreport
```

## 2. インストール資材のダウンロード

インストール資材をGitHubからダウンロードし、ホームディレクトリ直下(~/)に配置します。

```bash
$ cd ~
$ git clone https://github.com/nttcom/OsecT/

$ ls ~/OsecT/osect_sensor
Application  docker-compose.yml  Infrastructure  logs  tools
#これらのファイルが表示されることをご確認ください。

$ mv ~/OsecT/osect_sensor ~/
```

## 3. OsecTセンサーの設定

### 3.1. 監視ネットワークインタフェースの設定

まず、インタフェースを確認します。
```bash
ip a
```

設定箇所は3箇所です。

1箇所目：crontabを編集し、監視ネットワークを指定します。

```bash
$ vi ~/osect_sensor/conf/crontab
```

編集箇所

```bash
* * * * * /opt/ot_tools/suricata_cron.sh enp1s0 > /dev/null 2>&1
* * * * * /opt/ot_tools/p0f_cron.sh enp1s0 > /dev/null 2>&1
* * * * * /opt/ot_tools/yaf_cron.sh enp1s0 > /dev/null 2>&1
```

編集例：監視ネットワークインタフェースがenp0s8の場合

```bash
* * * * * /opt/ot_tools/suricata_cron.sh enp0s8 > /dev/null 2>&1
* * * * * /opt/ot_tools/p0f_cron.sh enp0s8 > /dev/null 2>&1
* * * * * /opt/ot_tools/yaf_cron.sh enp0s8 > /dev/null 2>&1
```

2箇所目：suricata.yamlを編集し、監視ネットワークを指定します。

```bash
$ vi ~/osect_sensor/conf/suricata.yaml
```

編集箇所

```bash
# Linux high speed capture support
af-packet:
  - interface: eth1
```

編集例：監視ネットワークインタフェースがenp0s8の場合

```bash
# Linux high speed capture support
af-packet:
  - interface: enp0s8
```

3箇所目：node.cfgを編集し、監視ネットワークを指定します。

```bash
$ vi ~/osect_sensor/conf/node.cfg
```

編集箇所

```bash
[worker-1]
type=worker
host=localhost
interface=af_packet::eth1
lb_method=custom
lb_procs=6
pin_cpus=0,1,2,3,4,5
```

編集例：監視ネットワークインタフェースがenp0s8の場合

```bash
[worker-1]
type=worker
host=localhost
interface=af_packet::enp0s8
lb_method=custom
lb_procs=6
pin_cpus=0,1,2,3,4,5
```

### 3.2. DjangoのSECRET_KEYの設定

DjangoのSECRET_KEYの設定を設定します。

```bash
$ SK=`cat /dev/urandom | base64 | fold -w 64 | head -n 1`; sed -i -e 's@SECRET_KEY = ""@SECRET_KEY = "'$SK'"@g' ~/osect_sensor/Application/edge_cron/edge_cron/settings.py
（何も表示されません。）
```

### 3.3. データ送信用URLの設定

NTT Comから提供されたデータ送信用URLを設定ファイルに記載します。

```bash
$ vi Application/edge_cron/common/common_config.py
```

記載箇所:

```python
API_URL = 'https://your url/paper/api/v1/createlogdata/post'
```

記載例:

```python
API_URL = 'https://xxxxx.osect.ntt.com/paper/api/v1/createlogdata/post'
```

### 3.4. クライアント証明書の設定

NTT Comから提供されたクライアント証明書を以下に格納します（ファイル名は変更しません）。

```bash
$ ~/osect_sensor/keys/client.pem
```

### 3.5. ログ送信方式の設定

有線経由でログを送信する場合は以下の設定をします。

設定ファイル:

```bash
$ vi Application/edge_cron/common/common_config.py
```

変更箇所:

```python
# 無線経由で送信
IS_CLOSED_NETWORK = True
↓
# 有線経由で送信
IS_CLOSED_NETWORK = False
```

設定ファイル:

```bash
$ vi docker-compose.yml
```

変更箇所:

```yml
    devices:
      - "/dev/ttyUSB1:/dev/ttyUSB1"
↓
（削除）
```

センサー一体型OsecTの場合は以下の設定をします。

```bash
$ vi Application/edge_cron/common/common_config.py
```

変更箇所:

```python
# センサー一体型のフラグ False
SENSOR_INTEGRATED_TYPE = False
↓
# センサー一体型のフラグ True
SENSOR_INTEGRATED_TYPE = True
```

設定ファイル:

```bash
$ vi docker-compose.yml
```

変更箇所:

```yml
    volumes:
      ...
      ...
      - ./conf/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek # zeek realtime
↓
    volumes:
      ...
      ...
      - ./conf/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek # zeek realtime
      - ~/edgesec_on_docker/logs/pcap/uploaded:/opt/edge_cron/paper/sc_src/input/pcap/server_uploaded # multiport
```

（参考）

センサー一体型OsecTである場合の```Application/edge_cron/common/common_config.py```の```LABEL_ID```設定は```label_name```を設定することです。

```
common_db=# select * from label_master;
 id | label_id | label_name | label_display_name 
----+----------+------------+--------------------
  1 | sensor1（ここを指定するではなく）  | default（ここを指定する）    | デフォルト
  2 | sensor2（ここを指定するではなく）  | sensor_1（ここを指定する）   | センサー１
(2 rows)
```

## 4. コンテナの構築・起動

コンテナを構築、起動します。

```bash
$ cd ~/osect_sensor/
$ /usr/local/bin/docker-compose build
$ /usr/local/bin/docker-compose up -d
```
