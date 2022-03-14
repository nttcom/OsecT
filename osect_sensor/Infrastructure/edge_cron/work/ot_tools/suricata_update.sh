#!/bin/bash

SURICATA_VERSION=`suricata -V | grep -o "[0-9]\.[0-9]\.[0-9]"`
DOWNLOAD_URL_PREFIX=https://rules.emergingthreats.net/open/suricata-${SURICATA_VERSION}/
DOWNLOAD_SIG_FILE=emerging.rules.tar.gz
DOWNLOAD_VER_FILE=version.txt

cd /home/work/

# Download signature version number
rm -f $DOWNLOAD_VER_FILE
wget ${DOWNLOAD_URL_PREFIX}${DOWNLOAD_VER_FILE}
if [ $? -ne 0 ]; then
  echo "failed to download ${DOWNLOAD_URL_PREFIX}${DOWNLOAD_VER_FILE}"
  exit 1
fi

# Compare with current signature version 
diff current_version $DOWNLOAD_VER_FILE > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "current version is the latest"
  exit 0
fi

# Download signature rules
rm -f $DOWNLOAD_SIG_FILE
wget ${DOWNLOAD_URL_PREFIX}${DOWNLOAD_SIG_FILE}
if [ $? -ne 0 ]; then
  echo "failed to download ${DOWNLOAD_URL_PREFIX}${DOWNLOAD_SIG_FILE}"
  exit 1
fi

# Compare MD5 checksum values
rm -f ${DOWNLOAD_SIG_FILE}.md5
REMOTE_MD5=`wget -O - ${DOWNLOAD_URL_PREFIX}${DOWNLOAD_SIG_FILE}.md5`
LOCAL_MD5=`md5sum ${DOWNLOAD_SIG_FILE} | grep -o '^\S*'`
if [ $REMOTE_MD5 != $LOCAL_MD5 ]; then
  echo "incorrect md5 value"
  exit 1
fi

# Extract signature rules
rm -rf rules
tar -xzf $DOWNLOAD_SIG_FILE
rm rules/emerging-ja3.rules
grep -h -ve "^#" -ve "^$" rules/*.rules > /var/lib/suricata/rules/suricata.rules
mv $DOWNLOAD_VER_FILE current_version

# Set versions
export SIGNATURE_VERSION=`cat current_version`
export SURICATA_VERSION=${SURICATA_VERSION}

python3.8 /opt/edge_cron/manage.py send_version
if [ $? -ne 0 ]; then
  echo "failed to send version"
  exit 1
fi
