SLEEP_TIME = 60
""" 監視インターバル """

TCPDUMP_SHELL_COMMAND = [
    "/usr/sbin/tcpdump",
    "-w",
    "realtime-%F-%T.pcap",
    "-G",
    "60",
    "-ni",
    "enp0s3",
    "-s",
    "0",
    "-Z",
    "root",
    "-z",
    "/opt/ot_tools/capture.sh",
]
""" tcpdumpの起動shellコマンド """

REMOVE_PCAP_FILE = "realtime-*.pcap"
