LABEL_ID = 'suricata'
""" 複数スイッチ対応用のラベルID """

PCAP_UPLOADING_FILE_PATH = 'paper/sc_src/input/pcap/uploading/'
"""pcapのアップロード先の配置パス"""

PCAP_UPLOADED_FILE_PATH = 'paper/sc_src/input/pcap/uploaded/'
"""pcapのアップロードが終わったファイルを配置するパス"""

PCAP_ANALYZE_FILE_PATH = 'paper/sc_src/input/pcap/analyze/'
"""解析中のpcap及び中間ファイルの配置パス"""

PCAP_COMPLETE_FILE_PATH = 'paper/sc_src/input/pcap/complete/'
"""全ての処理が終わったpcap及び中間ファイルの配置パス"""

PCAP_COMPLETE_ARCHIVES_FILE_PATH = 'paper/sc_src/input/pcap/complete_archives/'
"""全ての処理が終わったpcap及び中間ファイルのアーカイブパス"""

PCAP_SERVER_UPLOADING_FILE_PATH = 'paper/sc_src/input/pcap/server_uploading/'
""" ログ解析が終わったディレクトリをuploadするための一時領域 """

SURICATA_ENABLE = True
""" SURICATA使用フラグ（リアルタイム処理の場合はログを転送） """

FUNC_RESTRICTION = False
""" 機能制限版（建設版）フラグ。Trueの場合機能制限 """

YAF_ENABLE = True
""" yaf use flag """

BACNET_ENABLE = True
""" Bacnetトラフィックを取り込むか否か """

MODBUS_ENABLE = False
""" Modbusトラフィックを取り込むか否か """

BRO_SHELL_COMMAND = '/opt/ot_tools/bro.sh'
"""broのログ取得コマンド"""

P0F_SHELL_COMMAND = '/opt/ot_tools/p0f.sh'

P0F_AWK_COMMAND = '/opt/ot_tools/p0f-dic/p0f-dic-awk.sh'

BACNET_SHELL_COMMAND = '/opt/ot_tools/bacnet.sh'

SURICATA_SHELL_COMMAND = '/opt/ot_tools/suricata.sh'
""" SURICATAのログ取得コマンド """

YAF_SHELL_COMMAND = '/opt/ot_tools/yaf.sh'

SURICATA_YAML = '/opt/ot_tools/suricata.yaml'
""" SURICATAの設定ファイル保存場所 """

ALLOWED_PCAP_EXT = '.pcap,.cap,.pkt'
""" アップロード出来るPCAPファイルの拡張子 """

ALLOWED_LOG_EXT = '.zip'
""" アップロード出来るログファイルの拡張子 """

PCAP_TO_DB_CPU = 5
""" PCAPをログ化する際に使用するCPU数 """

API_URL = 'https://coe01.internal.osect.ntt.com/paper/api/v1/createlogdata/post'
""" SaaS連携用APIのURL """

TIME_OUT_VAL = 120
""" API接続時のタイムアウト値 """

PCAP_COMPLETE_COMPRESSION_LIMIT_DATE = 365
"""complete配下の保持期限切れファイルとディレクトリを圧縮対象にする日付（日）"""

PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_DATE = 365
"""complete_archives配下の保持期限切れファイルの削除対象にする日付（日）"""

PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY = 150
"""completeとcomplete_archivesの保持容量上限値（GB）"""

CLIENT_CERTIFICATE_PATH = '/etc/ssl/private/client.pem'
"""クライアント認証のための証明書・秘密鍵"""

SEND_VERSION_API_URL = 'https://coe01.internal.osect.ntt.com/paper/api/v1/sensor_status/post'
"""Suricataシグネチャのバージョンを送るURL"""
