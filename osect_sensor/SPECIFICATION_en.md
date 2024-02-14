# OsecT Sensor Specifications

## 1. Overview

OsecT sensor provides the following functions in SaaS type.

1. Generate communication logs: Generate communication logs from the monitoring network interface for analysis in the cloud.
2. Send communication logs: Send the communication log in function 1 to the cloud.
3. Generate support logs: Generate support logs for use in troubleshooting of the sensor PC.
4. Delete files: Delete the communication logs in function 2 after a certain period of time from its creation.

This document describes the following:

- Communication log generation and transmission specifications
- Support log generation specifications
- Security measures for log transmission

## 2. Communication log generation and transmission specifications

Communication logs are a collection of text files in log format that record information necessary for analysis in OsecT on the cloud.

Communication logs are generated and sent to the cloud at regular intervals. The default value for the generation/transmission cycle is 1 minute.

Communication logs do not contain control information of the production line.

The packets/frames targeted by each file, the information to be recorded, and the generation method are as follows.


Packets/frames targeted by each file, recorded information, and generation methods for each file are as follows.

### 2.1. IP connection Log

Description: The log of IP communication connection information

Target: IPv4 and IPv6 packets whose transport layer protocols are TCP, UDP, ICMP, and ICMPv6

Generation method: Zeek

File name: conn.log

Recording Information: the table below

- Zeek official information: <https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#detailed-interface>
- The host serving as the starting point for the connection is defined as the client, and the communication destination of the client is defined as the server.

| Information Name | Description |
| --- | --- |
| ts | timestamp of the first packet of the connection |
| uid | unique identification of the connection |
| id.orig_h | client IP address |
| id.orig_p | client port number (type, code for ICMP and ICMPv6) |
| id.resp_h | server IP address |
| id.resp_p | server port number (type, code for ICMP and ICMPv6) |
| proto | transport layer protocol |
| service | application layer protocol |
| duration | connection duration |
| orig_bytes | number of payload bytes sent by the client |
| resp_bytes | number of payload bytes sent by the server |
| conn_state | connection state |
| local_orig | (no record) |
| local_resp | (no record) |
| missed_bytes | number of bytes not delivered due to packet loss |
| history | connection state history |
| orig_pkts | number of packets sent by the client |
| orig_ip_bytes | number of IP-level bytes sent by the client |
| resp_pkts | number of packets sent by the server |
| resp_ip_bytes | number of IP-level bytes sent by the server |
| tunnel_parents | uid value of the encapsulated parent connection used during the lifespan of this internal connection when it is over a tunnel |
| orig_l2_addr | client MAC address |
| resp_l2_addr | server MAC address |


### 2.2. IP Flow Log

Description: The log of bidirectional flow information of IP communication

Target: IPv4 and IPv6 packets whose transport layer protocols are other than TCP, UDP, ICMP, and ICMPv6

Generation method: generate by the software developed by NTT Com based on data from the open source software YAF

File name: yaf_flow.log

Recording Information: the table below

- YAF official information: <https://tools.netsa.cert.org/yaf/yafscii.html#Human-Readable-Output>
- The host serving as the starting point for the connection is defined as the client, and the communication destination of the client is defined as the server.


| Information Name | Description |
| --- | --- |
| ts | start time the flow |
| start-time | start time the flow |
| end-time | end time of the flow |
| duration | flow duration |
| rtt | RTT |
| proto | IP protocol number |
| sip | client IP address |
| sp | client port number |
| dip | server IP address |
| dp | server port number |
| srcMacAddress | client's MAC address |
| dstMacAddress | server MAC address |
| iflags | TCP flags of the first packet sent by the client (TCP packets are not recorded since they are excluded from targets) |
| uflags | the union of TCP flags of the second and subsequent packets sent by the client (TCP packets are not recorded since they are excluded from targets) |
| riflags | TCP flags of the first packet sent by the server (TCP packets are not recorded since they are excluded from targets) |
| ruflags | the union of TCP flags of the second and subsequent packets sent by the server (TCP packets are not recorded since they are excluded from targets) |
| isn | TCP sequence number of the first packet sent by the client (TCP packets are not recorded since they are excluded from targets) |
| risn | TCP sequence number of the first packet sent by the server (TCP packets are not recorded since they are excluded from targets) |
| tag | VLAN tag of the first packet sent by the client |
| rtag | VLAN tag of the first packet sent by the server |
| pkt | number of packets sent by client |
| oct | number of bytes sent by client |
| rpkt | number of packets sent by the server |
| roct | number of bytes sent by the server |
| end-reason | the reason for the abnormal termination of the flow |

### 2.3. ARP Log

Description: The log of request and reply frame information for ARP (Address Resolution Protocol), which is MAC address resolution communication in IPv4

Target: ARP frame

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: arp.log

Recording Information: the table below

- The host sending ARP requests is defined as the originator, and the host targeted for MAC address resolution by the originator is defined as the responder.

| Information Name | Description |
| --- | --- |
| ts | frame time |
| orig_mac | originator MAC address |
| orig_ip | originator IP address |
| resp_mac | responder MAC address (only record ARP responses) |
| resp_ip | responder IP address |
| who_has | responder IP address (only record for ARP requests) |
| pkts | number of packet appearances |

### 2.4. NS Log

Description: The log of NS (Neighbor Solicitation) and NA (Neighbor Advertisement) packet information, which are MAC address resolution communication in IPv6

Target: IPv6 NS and NA packets

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: ns.log

Recording Information: the table below

- The host sending NS is defined as the originator, and the host targeted for MAC address resolution by the originator is defined as the responder.

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet |
| orig_mac | originator MAC address |
| orig_ip | originator IP address |
| resp_mac | MAC address of responder (record only for NA) |
| resp_ip | responder IP address |
| who_has | responder IP address (record only for NS) |
| pkts | number of packet appearances |

### 2.5. DNS Log

Description: The log of DNS packet information for name resolution communication

Target: DNS packets (all DNS-shaped protocols, including NetBIOS Name Service, mDNS, LLMNR, and others, not limited to port 53/udp)

Generation method: Zeek

File name: dns.log

Recording Information: the table below

- Zeek official information: <https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html#id2>
- The host sending DNS queries is defined as the client and the host receiving the client's communication is defined as the server.

| Information Name | Description |
| --- | --- |
| ts | timestamp of earliest connection associated with DNS messages |
| uid | unique identification for DNS communication connection |
| id.orig_h | client IP address |
| id.orig_p | client port number |
| id.resp_h | server IP address |
| id.resp_p | server port number |
| proto | transport layer protocol |
| trans_id | transaction ID |
| rtt | RTT of query and response |
| query | domain name of the query |
| qclass | QCLASS value indicating the query class |
| qclass_name | descriptive name of the query class |
| qtype | QTYPE value indicating the query type |
| qtype_name | descriptive name indicating the query type |
| rcode | response code |
| rcode_name | descriptive name indicated by the response code |
| AA | AA bit of response |
| TC | TC bit |
| RD | RD bit of the query |
| RA | RA bit of the response |
| Z | reserved fields that remains zero in query and response |
| answers | resource description of the query answer |
| TTL | the cache interval for the RR corresponding to the answer field |
| rejected | whether the query is rejected by the server |
| pkts | number of packet appearances |

### 2.6. p0f Log

Description: The log of TCP packet information

Target: TCP SYN, SYN+ACK packets

Recording Information: the table below

Generation method: generate by NTT Com modified version of open source software p0f <https://github.com/nttcom/OsecT/tree/main/p0f-k>

File name: p0f-k.log

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet |
| mod | SYN or SYN+ACK |
| src_ip | source IP address |
| src_mac | source MAC address |
| os | OS estimation results |
| raw_sig | signature for OS estimation |

### 2.7. HTTP Log

Description: The log of HTTP packet information

Target: HTTP packets (all HTTP format, not limited to port=80/tcp)

Generation method: Zeek

File name: http.log

Recording Information: the table below

- Zeek official information <https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info>
- The host sending HTTP requests is defined as the client, and the communication destination of the client is defined as the server.

| Information Name | Description |
| --- | --- |
| ts | timestamp of the request |
| uid | unique identification of the connection |
| id.orig_h | client IP address |
| id.orig_p | client port number |
| id.resp_h | server IP address |
| id.resp_p | server port number |
| trans_depth | the depth of the pipeline for the connection of request/response transactions |
| method | request method (GET, POST, HEAD, etc.) |
| host | header value of the host|
| uri | request URI |
| referrer | header value the referrer |
| version | value of the version part in the request |
| user_agent | header value of User-Agent sent by the client |
| origin | Origin header value from the client |
| request_body_len | actual content size of data sent by the client |
| response_body_len | actual content size of data sent by the server |
| status_code | status code returned by the server |
| status_msg | status message returned by the server |
| info_code | reply code of last 1xx information returned by the server |
| info_msg | reply message of last 1xx information returned by the server |
| tags | indicators of various attributes associated with request/response pairs |
| username | username of basic authentication |
| password | (no record) |
| proxied | all headers indicating whether the request is proxied or not |
| orig_l2_addr | client MAC address |
| resp_l2_addr | server MAC address |

### 2.8. DHCP Log

Description: The log of DHCP packet information

Target: DHCP request packets (destination port=67/UDP/IPv4 only)

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: dhcp2.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet time |
| src_iP | source IP address |
| src_mac | source MAC address |
| hostname | Option12 (Hostname) sent by the DHCP client |
| parameter_list | Option55 (Parameter List) sent by the DHCP client |
| class_id | Option60 (Class Id) sent by the DHCP client |

### 2.9. NetBIOS NameService Log

Description: The log of NetBIOS NameService packet information

Target: NetBIOS NameService request packets (destination port=137/UDP only)

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: netbios-ns.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet time |
| src_iP | source IP address |
| src_mac | source MAC address |
| name | name value of additional records |
| ttl | TTL value of additional records |
| service_type | part of name flags of additional records |

### 2.10. CIFS Browser Protocol Log

Description: The log of CIFS browser protocol packet information

Target: CIFS browser protocol packets (destination port=138/UDP only)

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: mswin-browser.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet time |
| src_iP | source IP address |
| src_mac | source MAC address |
| server_name | header value of server name |
| os_version | header value of OS version |
| server_type | header value of server type |
| browser_version | header value of browser version  |
| signature | header value of signature |
| host_comment | header value of host comment |

### 2.11. DHCPv6 Log

Description: The log of DHCPv6 packet information

Target: DHCPv6 request packets (destination port=547/UDP/IPv6 only)

Generation method: Generated by open source software Zeek and Zeek script developed by NTT Com

File name: dhcpv6.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet time |
| src_iP | source IP address |
| src_mac | source MAC address |
| hostname | Option39 (Client FQDN) sent by DHCPv6 client |
| finger_print | Option6 (Option Request) sent by DHCPv6 client |
| enterprise_number | part of Option16 (Vendor Class) sent by DHCPv6 client |
| vendor_class | part of Option16 (Vendor Class) sent by DHCPv6 client |

### 2.12. SSDP Log

Description: The log of SSDP (Simple Service Discovery Protocol) packet information

Target: SSDP packets (destination port=1900/UDP and response to this)

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: ssdp.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of the packet time |
| src_ip | source IP address |
| src_mac | source MAC address |
| method | method (M-Seatch, Advertise, etc.) |
| server_or_user_agent | value of SERVER field or USE-AGENT field |

### 2.13. CC-Link IE Field Basic Log

Description: The log of CC-Link IE Field Basic packet information

Target: CC-Link IE Field Basic packets

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: cclink-ief-basic.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of first communication |
| uid | unique identification |
| id.orig_h | source IP address |
| id.orig_p | source port number |
| id.resp_h | destination IP address |
| id.resp_p | destination port number |
| pdu | protocol function name |
| cmd | `cyclic` or `-` |
| number | number of packet appearances |
| ts_end | timestamp of last communication |

### 2.14. CC-Link IE Field, IE Control Log

Description: The log of CC-Link IE Field, IE Control packet information

Target: CC-Link IE Field, IE Control packets

Generation method: open source software Zeek and Zeek script developed by NTT Com

File name: cclink-ie.log

Recording Information: the table below

| Information Name | Description |
| --- | --- |
| ts | timestamp of first communication |
| src_mac | source MAC address |
| dst_mac | destination MAC address |
| service | protocol name |
| pdu_type | protocol function name |
| cmd | specific fields of transient1 and transient2 |
| node_type | node type |
| node_id | node identifier |
| connection_info | transientData identifier |
| src_node_number | source node number |
| number | number of packet appearances |
| ts_end | timestamp of last communication |

### 2.15. Signature Detection Log

Description: The log of signature detection alerts

Target and recording information: It performs signature matching on all packets and keep records of detection alerts when signature matching occurs.

Generation method: open source software Suricata and Proofpoint Emerging Threats Rules for signature rules

- Suricata: <https://suricata.io/>
- Proofpoint Emerging Threats Rules: <http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz>

File name: eve.json

## 3. Support log generation specifications

Support logs are a group of files that record information necessary for troubleshooting of the sensor PC.

Support logs are generated by sosreport command. Sosreport is a tool that collects information of Linux OS configuration, system, and diagnosis.

- Sosreport manual: <http://manpages.ubuntu.com/manpages/bionic/man1/sosreport.1.html>

In addition to the standard sosreport information, OsecT sensor also collects the following information:

- Docker host log
- Logs regarding communication log creation function and transmission processing

As of August 7th, 2023, support log generation only occurs when a command is executed.

## 4. Security measures for log transmission

The following will be implemented as security measures when uploading communication logs to the cloud.

- TLS encryption
- Server/client authentication by public key certificate
- Data upload through closed network by NTT Com's ICMS (IoT Connect Mobile Type S) and FIC (Flexible InterConnect)
