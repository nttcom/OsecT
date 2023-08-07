# OsecTセンサーの仕様

## 1. 概要

OsecTセンサーはSaaS型OsecTにおいて、以下の機能を提供します。

1. 通信ログ生成: 監視用ネットワークインタフェースからクラウドでの分析用の通信ログを生成します。
2. 通信ログ送信: 1の通信ログをクラウドに送信します。
3. サポートログ生成: センサーPCのトラブルルシュートに使用するためのサポートログを生成します。
4. サポートログ送信: 4のサポートログをクラウドに送信します。
5. ファイル削除: 生成から一定期間経過した1のPCAPファイル及び2の通信ログを削除します。

本ドキュメントでは、以下について記載します。

- 通信ログの生成・送信仕様
- サポートログの生成・送信仕様
- ログ送信におけるセキュリティ対策

## 2. 通信ログの生成・送信仕様

通信ログは、クラウド上でのOsecTにおいて分析に必要となる情報を記録したログ形式のテキストファイル群です。

通信ログの生成、クラウドへの送信は一定周期で行われます。生成・送信の周期の規定値は1分です。

通信ログには製造ラインの制御情報は含まれません。

各ファイルの対象とするパケット/フレーム、記録する情報、生成方法は以下の通りです。

### 2.1. IPコネクションログ

概要: IP通信のコネクション情報を記録

対象: トランスポート層プロトコルがTCP, UDP, ICMP, ICMPv6のIPv4およびIPv6パケット

生成方法: オープンソースソフトウェアZeekにより生成

ファイル名: conn.log

記録する情報: 下表

- Zeekの公式情報: <https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#detailed-interface>
- コネクションの起点となる端末をクライアント、クライアントの通信先をサーバと定義

| 情報名 | 説明 |
| --- | --- |
| ts | コネクションの最初のパケットの時刻 |
| uid | コネクションの個別識別ID |
| id.orig_h | クライアントのIPアドレス |
| id.orig_p | クライアントのポート番号（ICMP, ICMPv6の場合はType, Code） |
| id.resp_h | サーバのIPアドレス |
| id.resp_p | サーバのポート番号（ICMP, ICMPv6の場合はType, Code） |
| proto | トランスポート層プロトコル |
| service | アプリケーション層プロトコル |
| duration | コネクションの継続時間 |
| orig_bytes | クライアントが送ったペイロードのバイト数 |
| resp_bytes | サーバが送ったペイロードのバイト数 |
| conn_state | コネクションの状態 |
| local_orig | （記録しない） |
| local_resp | （記録しない）  |
| missed_bytes | パケット損失によって届かなかったバイト数 |
| history | コネクションの状態履歴 |
| orig_pkts | クライアントが送ったパケット数 |
| orig_ip_bytes | クライアントが送ったIPレベルのバイト数 |
| resp_pkts | サーバが送ったパケット数 |
| resp_ip_bytes | サーバが送ったIPレベルのバイスト数 |
| tunnel_parents | コネクションがトンネルを介していた場合におけるこの内部コネクションの存続期間中に使用されたカプセル化された親接続のuid値 |
| orig_l2_addr | クライアントのMACアドレス |
| resp_l2_addr | サーバのMACアドレス |

### 2.2. IPフローログ

概要: IP通信の双方向フロー情報を記録

対象: トランスポート層プロトコルがTCP, UDP, ICMP, ICMPv6以外のIPv4およびIPv6パケット

生成方法: オープンソースソフトウェアYAFにより生成したデータを元にNTT Com開発のソフトウェアにより生成

ファイル名: yaf_flow.log

記録する情報: 下表

- YAFの公式情報: <https://tools.netsa.cert.org/yaf/yafscii.html#Human-Readable-Output>
- コネクションの起点となる端末をクライアント、クライアントの通信先をサーバと定義

| 情報名 | 説明 |
| --- | --- |
| ts | フローの開始時刻 |
| start-time | フローの開始時刻 |
| end-time | フローの終了時刻 |
| duration | フローの継続時間 |
| rtt | RTT |
| proto | IPプロトコル番号 |
| sip | クライアントのIPアドレス |
| sp | クライアントのポート番号 |
| dip | サーバのIPアドレス |
| dp | サーバのポート番号 |
| srcMacAddress | クライアントのMACアドレス |
| dstMacAddress | サーバのMACアドレス |
| iflags | クライアントが送った最初のパケットのTCPフラグ（TCPパケットは対象外のため記録しない） |
| uflags | クライアントが送った2番目以降のパケットのTCPフラグの和集合（TCPパケットは対象外のため記録しない） |
| riflags | サーバが送った最初のパケットのTCPフラグ（TCPパケットは対象外のため記録しない） |
| ruflags | サーバが送った2番目以降のパケットのTCPフラグの和集合（TCPパケットは対象外のため記録しない） |
| isn | クライアントが送った最初のパケットのTCPシーケンス番号（TCPパケットは対象外のため記録しない） |
| risn | サーバが送った最初のパケットのTCPシーケンス番号（TCPパケットは対象外のため記録しない） |
| tag | クライアントが送った最初のパケットのVLANタグ |
| rtag | サーバが送った最初のパケットのVLANタグ |
| pkt | クライアントが送ったパケット数 |
| oct | クライアントが送ったバイト数 |
| rpkt | サーバが送ったパケット数 |
| roct | サーバが送ったバイト数 |
| end-reason | フローが正常終了しなかった場合の理由 |

### 2.3. ARPログ

概要: IPv4におけるMACアドレス解決通信であるARP(Address Resolution Protocol)のリクエスト及びリプライフレーム情報を記録

対象: ARPフレーム

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: arp.log

記録する情報: 下表

- ARPリクエストを送信する端末をオリジネーター、オリジネーターがMACアドレス解決する対象となる端末をレスポンダーと定義

| 情報名 | 説明 |
| --- | --- |
| ts | フレームの時刻 |
| orig_mac | オリジネーターのMACアドレス |
| orig_ip | オリジネーターのIPアドレス |
| resp_mac | レスポンダーのMACアドレス（ARP応答の場合のみ記録） |
| resp_ip | レスポンダーのIPアドレス |
| unsolicited | （記録しない） |
| no_resp | （記録しない） |
| who_has | レスポンダーのIPアドレス（ARP要求の場合のみ記録） |
| is_at | （記録しない） |

### 2.4. NSログ

概要: IPv6におけるMACアドレス解決通信であるNS（Neighbor Solicitation）及びNA（Neighbor Advertisement）のパケット情報を記録

対象: IPv6 NS及びNAパケット

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: ns.log

記録する情報: 下表

- NSを送信する端末をオリジネーター、オリジネーターがMACアドレス解決する対象となる端末をレスポンダーと定義

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| orig_mac | オリジネーターのMACアドレス |
| orig_ip | オリジネーターのIPアドレス |
| resp_mac | レスポンダーのMACアドレス（NAの場合のみ記録） |
| resp_ip | レスポンダーのIPアドレス |
| who_has | レスポンダーのIPアドレス（NSの場合のみ記録） |

### 2.5. DNSログ

概要: 名前解決通信であるDNSのパケット情報を記録

対象: DNSパケット（ポート=53/udpに限らず、NetBIOS Name Service、mDNS、LLMNRなどのDNS形状のもの全て）

生成方法: オープンソースソフトウェアZeekにより生成

ファイル名: dns.log

記録する情報: 下表

- Zeek公式情報: <https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html#id2>
- DNSクエリを送信する端末をクライアント、クライアントの通信先の端末をサーバと定義

| 情報名 | 説明 |
| --- | --- |
| ts | DNSメッセージに紐づくコネクションのうち最も早い時刻 |
| uid | DNS通信のコネクションの個別識別ID |
| id.orig_h | クライアントのIPアドレス |
| id.orig_p | クライアントのポート番号 |
| id.resp_h | サーバのIPアドレス |
| id.resp_p | サーバのポート番号 |
| proto | トランスポート層プロトコル |
| trans_id | トランザクションID |
| rtt | クエリとレスポンスのRTT |
| query | クエリのドメイン名 |
| qclass | クエリのクラスを示すQCLASS値 |
| qclass_name | クエリのクラスの記述名 |
| qtype | クエリのタイプを示すQTYPE値 |
| qtype_name | クエリのタイプを示す記述名 |
| rcode | レスポンスのレスポンスコード |
| rcode_name | レスポンスのレスポンスコードが示す記述名 |
| AA | レスポンスのAAビット |
| TC | TCビット |
| RD | クエリのRDビット |
| RA | レスポンスのRAビット |
| Z | クエリとレスポンスで通常うゼロとなる予約フィールド |
| answers | クエリ回答のリソースディスクリプション |
| TTL | answersフィールドに対応するRRのキャシュ間隔 |
| rejected | サーバによってクエリが拒否されたか否か |

### 2.6. p0fログ

概要: TCPパケット情報を記録

対象: TCP SYN, SYN+ACKパケット

記録する情報: 下表

生成方法: オープンソースソフトウェアp0fのNTT Com改造版 <https://github.com/nttcom/OsecT/tree/main/p0f-k> により生成

ファイル名: p0f-k.log

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| mod | SYN or SYN+ACK  |
| src_ip | 送信元IPアドレス |
| src_mac | 送信元MACアドレス |
| os | OS推定結果 |
| raw_sig | OS推定に使用するシグニチャー |

### 2.7. HTTPログ

概要: HTTPパケット情報を記録

対象: HTTPパケット（ポート=80/tcpに限らず、HTTP形式のもの全て）

生成方法: オープンソースソフトウェアZeekにより生成

ファイル名: http.log

記録する情報: 下表

- Zeek公式情報 <https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info>
- HTTPリクエストを送信する端末をクライアント、クライアントの通信先の端末をサーバと定義

| 情報名 | 説明 |
| --- | --- |
| ts | リクエストが発生した時刻 |
| uid | コネクションの個別識別ID |
| id.orig_h | クライアントのIPアドレス |
| id.orig_p | クライアントのポート番号 |
| id.resp_h | サーバのIPアドレス |
| id.resp_p | サーバのポート番号 |
| trans_depth | リクエスト/レスポンスのトランザクションのコネクションへのパイプラインの深さ |
| method | リクエストのメソッド（GET, POST, HEAD等） |
| host | HOSTヘッダの値 |
| uri | リクエストのURI |
| referrer | refererヘッダの値 |
| version | リクエストのバージョン部分の値 |
| user_agent | クライアントが送信したUser-Agentヘッダの値 |
| origin | クライアントからOriginヘッダの値 |
| request_body_len | クライアントからの送信データのコンテンツサイズの実際のサイズ |
| response_body_len | サーバからの送信データのコンテンツサイズの実際のサイズ |
| status_code | サーバから返却されたステータスコード |
| status_msg | サーバから返却されたステータスメッセージ |
| info_code | サーバから返却された最終1xx infotmationのリプライコード |
| info_msg | サーバから返却された最終1xx infotmationのリプライメッセージ |
| tags | リクエスト/レスポンスのペアに関連付けられる様々な属性のインジケータ |
| username | Basic認証のユーザ名 |
| password | （記録しない） |
| proxied | リクエストがプロキシ中継されたかどうかを示すすべてのヘッダ |
| orig_l2_addr | クライアントのMACアドレス |
| resp_l2_addr | サーバのMACアドレス |

### 2.8. DHCPログ

概要: DHCPパケット情報を記録

対象: DHCPリクエストパケット（宛先ポート=67/UDP/IPv4のみ）

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: dhcp2.log

記録する情報: 下表

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| src_iP | 送信元IPアドレス |
| src_mac | 送信元MACアドレス |
| hostname | DHCPクライアントが送信するOption12（Hostname） |
| parameter_list | DHCPクライアントが送信するOption55（Parameter List） |
| class_id | DHCPクライアントが送信するOption60（Class Id） |

### 2.9. NetBIOS NameServiceログ

概要: NetBIOS NameServiceパケット情報を記録

対象: NetBIOS NameService要求パケット（宛先ポート=137/UDPのみ）

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: netbios-ns.log

記録する情報: 下表

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| src_iP | 送信元IPアドレス |
| src_mac | 送信元MACアドレス |
| name | Additional RecordsのName値 |
| ttl | Additional RecordsのTTL値 |
| service_type | Additional RecordsのName flagsの一部 |

### 2.10. CIFS Browser Protocolログ

概要: CIFS Browser Protocolパケット情報を記録

対象: CIFS Browser Protocolパケット（宛先ポート=138/UDPのみ）

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: mswin-browser.log

記録する情報: 下表

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| src_iP | 送信元IPアドレス |
| src_mac | 送信元MACアドレス |
| server_name | Server Nameヘッダの値 |
| os_version | OS Versionヘッダの値 |
| server_type | Server Typeヘッダの値 |
| browser_version | Browser Versionヘッダの値 |
| signature | Signatureヘッダの値 |
| host_comment | Host Commentヘッダの値 |

### 2.11. DHCPv6ログ

概要: DHCPv6パケット情報を記録

対象: DHCPv6要求パケット（宛先ポート=547/UDP/IPv6のみ）

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: dhcpv6.log

記録する情報: 下表

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| src_iP | 送信元IPアドレス |
| src_mac | 送信元MACアドレス |
| hostname | DHCPv6クライアントが送信するOption39（Client FQDN） |
| finger_print | DHCPv6クライアントが送信するOption6（Option Request） |
| enterprise_number | DHCPv6クライアントが送信するOption16（Vendor Class）の一部 |
| vendor_class | DHCPv6クライアントが送信するOption16（Vendor Class）の一部 |

### 2.12. SSDPログ

概要: SSDP（Simple Service Discovery Protocol）パケット情報を記録

対象: SSDPパケット（宛先ポート=1900/UDPおよびこれへの応答）

生成方法: オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名: ssdp.log

記録する情報: 下表

| 情報名 | 説明 |
| --- | --- |
| ts | パケットの時刻 |
| src_ip | 送信元IPアドレス |
| src_mac | 送信元MACアドレス |
| method | メソッド（M-Seatch, Advertise等） |
| server_or_user_agent | SERVERフィールドもしくはUSE-AGENTフィールドの値 |

### 2.13. CC-Link IE Field Basicログ

概要：CC-Link IE Field Basicパケット情報を記録

対象：CC-Link IE Field Basicパケット

生成方法：オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名：cclink-ief-basic.log

記録する情報：下表

| 情報名 | 説明 |
| --- | --- |
| ts | 最初に通信した時のタイムスタンプ |
| uid | ユニークID |
| id.orig_h | 送信元IPアドレス |
| id.orig_p | 送信元ポート番号 |
| id.resp_h | 宛先IPアドレス |
| id.resp_p | 宛先ポート番号 |
| pdu | プロトコルの関数名 |
| cmd | `cyclic` または `-` |
| number | パケット出現回数 |
| ts_end | 最後に通信した時のタイムスタンプ |

### 2.14. CC-Link IE Field, IE Controlログ

概要：CC-Link IE Field, IE Controlパケット情報を記録

対象：CC-Link IE Field, IE Controlパケット

生成方法：オープンソースソフトウェアZeek及びNTT Com開発のZeekスクリプトにより生成

ファイル名：cclink-ie.log

記録する情報：下表

| 情報名 | 説明 |
| --- | --- |
| ts | 最初に通信した時のタイムスタンプ |
| src_mac | 送信元MACアドレス |
| dst_mac | 宛先MACアドレス |
| service | プロトコル名 |
| pdu_type | プロトコルの関数名 |
| cmd | transient1とtransient2の特有のフィールド |
| node_type | ノード種別 |
| node_id | ノード識別子 |
| connection_info | transientDataの識別子 |
| src_node_number | 自ノード番号 |
| number | パケット出現回数 |
| ts_end | 最後に通信した時のタイムスタンプ |

### 2.15. シグニチャー検知ログ

概要: シグニチャー検知アラートを記録

対象及び記録する情報: 全てのパケットを対象としてシグニチャー突合を行い、シグネチャマッチ時の検知アラートを記録

生成方法: オープンソースソフトウェアSuricataにより生成。シグニチャーのルールにはProofpoint Emerging Threats Rulesを使用。

- Suricata: <https://suricata.io/>
- Proofpoint Emerging Threats Rules: <http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz>

ファイル名: eve.json

## 3. サポートログの生成・送信仕様

サポートログは、センサーPCのトラブルルシュートに必要となる情報を記録したファイル群です。

サポートログはsosreportコマンドを使って生成します。sosreportは、Linux OSの設定情報、システム情報、および診断情報をLinuxシステムから収集するツールです。

- sosreportのマニュアル: <http://manpages.ubuntu.com/manpages/bionic/man1/sosreport.1.html>

OsecTセンサーではsosreport標準の情報に加えて、以下の情報を収集します。

- Dockerホストのログ
- 通信ログ作成機能・送信処理に関するログ

2023年8月7日現在、サポートログの生成は、コマンド実行時にのみ行われます。

## 4. ログ送信におけるセキュリティ対策

通信ログのクラウドへのアップロード時のセキュリティ対策として、以下を実施します。

- TLSによる暗号化
- 公開鍵証明書によるサーバ/クライアント認証
- NTT ComのUNO(Arcstar Universal One)およびFIC(Flexible InterConnect)を用いた閉域ネットワーク経由でのデータアップロード
