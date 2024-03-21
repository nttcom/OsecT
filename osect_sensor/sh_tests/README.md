# sh_tests/ot_tools
`Infrastructure/edge_cron/work/ot_tools`配下のスクリプトをテストするためのコードを格納するディレクトリ。

本ディレクトリ内のファイルは、全てDocker container内で実行する前提。

## ディレクトリの基本構成
```
OsecT/osect_sensor/sh_tests$ tree .
.
├── common.sh                       # テスト用の関数や変数を記述
├── ot_tools
│   ├── bro
│   │   ├── bro_unfixed.sh        # 修正前のコード
│   │   ├── data                  # テスト用データの生成、保管先ディレクトリ
│   │   │   ├── expected
│   │   │   └── init
│   │   └── test.sh　　　　　　　 # 実際のテストコードを記述したスクリプト
│   ├── p0f
│   │   ├── data
│   │   │   ├── expected
│   │   │   └── init
│   │   ├── p0f_unfixed.sh
│   │   └── test.sh
│   ├── suricata
│   │   ├── data
│   │   │   ├── expected
│   │   │   └── init
│   │   ├── suricata_unfixed.sh
│   │   └── test.sh
│   └── yaf
│       ├── data
│       │   ├── expected
│       │   ├── gen_pcap.sh       # テスト用のデータ(pcap)を生成するスクリプト
│       │   └── init
│       │       └── udplite.pcap  # テスト用のオリジナルデータ(IPアドレスを書き換えて利用)
│       ├── test.sh
│       └── yaf_unfixed.sh
└── test_all.sh                     # 各テストコードを呼び出すスクリプト
```
