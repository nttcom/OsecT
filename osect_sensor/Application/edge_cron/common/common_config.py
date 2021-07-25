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
""" SURICATA使用フラグ """

FUNC_RESTRICTION = False
""" 機能制限版（建設版）フラグ。Trueの場合機能制限 """

YAF_ENABLE = True
""" yaf use flag """

BACNET_ENABLE = True
""" Bacnetトラフィックを取り込むか否か """

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

PCAP_TO_DB_CPU = 5
""" PCAPをログ化する際に使用するCPU数 """

API_URL = 'https://your url/paper/api/v1/createlogdata/post'
""" SaaS連携用APIのURL """

TIME_OUT_VAL = 120
""" API接続時のタイムアウト値 """

PCAP_COMPLETE_COMPRESSION_LIMIT_DATE = 30
"""complete配下の保持期限切れファイルとディレクトリを圧縮対象にする日付（日）"""

PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_DATE = 30
"""complete_archives配下の保持期限切れファイルの削除対象にする日付（日）"""

PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY = 100
"""completeとcomplete_archivesの保持容量上限値（GB）"""
