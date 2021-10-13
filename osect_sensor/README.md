# OsecTセンサーのインストール手順

## 0. 前提

動作確認済の機種は以下の通りです。

- [OKI AIエッジコンピューター「AE2100」](https://www.oki.com/jp/AIedge/)

また、Ubuntu 18.04.5 LTSで動作確認済みです。

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
$ sudo docker container run --rm hello-world
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

設定ファイルを編集し、監視ネットワークを指定します。

```bash
$ vi ~/osect_sensor/Application/edge_tcpdump/common/app_config.py
```

編集箇所

```python
TCPDUMP_SHELL_COMMAND = ['/usr/sbin/tcpdump', '-w', 'realtime-%F-%T.pcap', '-G', '60', '-ni', 'enp0s3', '-s', '0', '-z', '/opt/ot_tools/capture.sh']
````

編集例：監視ネットワークインタフェースがenp0s8の場合

```python
TCPDUMP_SHELL_COMMAND = ['/usr/sbin/tcpdump', '-w', 'realtime-%F-%T.pcap', '-G', '60', '-ni', 'enp0s8', '-s', '0', '-z', '/opt/ot_tools/capture.sh']
```

### 3.2. DjangoのSECRET_KEYの設定

DjangoのSECRET_KEYの設定を設定します。

```bash
$ SK=`cat /dev/urandom | base64 | fold -w 64 | head -n 1`; echo "SECRET_KEY='$SK'" > ~/osect_sensor/Application/edge_cron/edge_cron/local_settings.py
（何も表示されません。）
$ SK=`cat /dev/urandom | base64 | fold -w 64 | head -n 1`; echo "SECRET_KEY='$SK'" > ~/osect_sensor/Application/edge_tcpdump/sc_tcpdump/local_settings.py
（何も表示されません。）
```

### 3.3. データ送信用URLの設定

NTT Comから提供されたデータ送信用URLを設定ファイルに記載します。

```bash
$ vi Application/edge_cron/common/common_config.py
```

記載箇所:

```python
API_URL = ''
```

記載例:

```python
API_URL = 'https://xxxxx.osect.ntt.com/paper/api/v1/createlogdata/post'
```

### 3.4. OAuth 2.0 クライアント IDの設定

NTT Comから提供されたOAuth 2.0 クライアント IDを設定ファイルに記載します。

```bash
$ vi ~/osect_sensor/Application/edge_cron/auth/google_account.py
```

記載箇所:

```python
IAP_CLIENT_ID = ''
```

記載例:

```python
IAP_CLIENT_ID = 'xxxxxxxxxxxxxxxxx.apps.googleusercontent.com'
```

### 3.5. サービスアカウントキーファイルの配置

NTT Comから提供されたサービスアカウントキーファイルを所定のディレクトリに配置します。

ファイル名:

- `service_account.json`　（提供時から変更しない）

配置ディレクトリ:

- `~/osect_sensor/Application/edge_cron/auth/`

## 4. コンテナの構築・起動

コンテナを構築、起動します。

```bash
$ cd ~/osect_sensor/
$ sudo /usr/local/bin/docker-compose build
$ sudo /usr/local/bin/docker-compose up -d
```
