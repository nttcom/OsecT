##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
redef digest_salt = "Please change this value.";
redef ignore_checksums = T;
redef LogAscii::enable_utf_8 = F;

# This script logs which scripts were loaded during each run.
#@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
#@load tuning/defaults

# Estimate and log capture loss.
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Load the scan detection script.  It's disabled by default because
# it often causes performance issues.
#@load misc/scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
#@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
#@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
#@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
#@load protocols/ftp/software
#@load protocols/smtp/software
#@load protocols/ssh/software
#@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
#@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
#@load protocols/ftp/detect

# Scripts that do asset tracking.
# @load protocols/conn/known-hosts
# @load protocols/conn/known-services
# @load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
# @load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
# @load protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
# @load protocols/ssl/notary

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
#@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
#@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
#@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
#@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
# @load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
# @load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
#@load policy/frameworks/notice/extend-email/hostnames

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
# @load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
# @load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
# @load policy/protocols/conn/mac-logging

# Uncomment this to source zkg's package state
# @load packages

@load arp
@load ns
#@load zeek-plugin-enip
#@load zeek-plugin-profinet
#@load zeek-plugin-s7comm
#@load icsnpp-ethercat
@load icsnpp-modbus
@load zeek-long-connections
@load zeek-af_packet-plugin
@load zeek-parser-CCLinkFieldBasic
@load zeek-parser-CIFS-COM
@load zeek-parser-CIFS-NBNS-COM
@load zeek-parser-DHCPv4-COM
@load zeek-parser-DHCPv6-COM
@load zeek-parser-SSDP-COM
@load cc_link_noip
@load cc_link_tsn_slmp
@load cc_link_tsn_ptp

# セッション接続されたままパケットが1分以上流れない場合はセッションを閉じる
redef Conn::analyzer_inactivity_timeouts += {
        # For interactive services, allow longer periods of inactivity.
        [[Analyzer::ANALYZER_SSH, Analyzer::ANALYZER_FTP]] = 1min,
};

# セッション接続されたままパケットが1分以上流れない場合はセッションを閉じる
redef Conn::port_inactivity_timeouts += {
                [[21/tcp, 22/tcp, 23/tcp, 513/tcp, 61450/udp]] = 1min,
};

# 1分おきにconn_long.logを出力
redef LongConnection::default_durations = LongConnection::Durations(1min);
redef LongConnection::repeat_last_duration=T;

# conn.logのtsをログ出力時間に変更
hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter) {
        rec$ts = network_time();
}

redef record Conn::Info += {
        prev_orig_bytes: count &default=0;
        prev_resp_bytes: count &default=0;
        prev_orig_pkts: count &default=0;
        prev_orig_ip_bytes: count &default=0;
        prev_resp_pkts: count &default=0;
        prev_resp_ip_bytes: count &default=0;
};

hook LongConnection::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter) {
        rec$ts = network_time();

        local tmp_orig_bytes = rec$orig_bytes;
        rec$orig_bytes = rec$orig_bytes - rec$prev_orig_bytes;
        rec$prev_orig_bytes = tmp_orig_bytes;

        local tmp_resp_bytes = rec$resp_bytes;
        rec$resp_bytes = rec$resp_bytes - rec$prev_resp_bytes;
        rec$prev_resp_bytes = tmp_resp_bytes;

        local tmp_orig_pkts = rec$orig_pkts;
        rec$orig_pkts = rec$orig_pkts - rec$prev_orig_pkts;
        rec$prev_orig_pkts = tmp_orig_pkts;

        local tmp_orig_ip_bytes = rec$orig_ip_bytes;
        rec$orig_ip_bytes = rec$orig_ip_bytes - rec$prev_orig_ip_bytes;
        rec$prev_orig_ip_bytes = tmp_orig_ip_bytes;

        local tmp_resp_pkts = rec$resp_pkts;
        rec$resp_pkts = rec$resp_pkts - rec$prev_resp_pkts;
        rec$prev_resp_pkts = tmp_resp_pkts;

        local tmp_resp_ip_bytes = rec$resp_ip_bytes;
        rec$resp_ip_bytes = rec$resp_ip_bytes - rec$prev_resp_ip_bytes;
        rec$prev_resp_ip_bytes = tmp_resp_ip_bytes;
}
