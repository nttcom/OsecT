# OsecT

English is [here](README_en.md)

## OsecTとは

OsecT（オーセクト）は、多様なプロトコルが存在する制御システムのネットワークからデータを収集・蓄積・分析することで、制御システムを構成する機器や通信状況および、セキュリティ上の脆弱性や脅威など安全上のリスクを可視化する技術です。

## 特長

主な特長は以下の通りです。

### 制御システムに影響を与えることなく導入可能

- スイッチのミラーポートに接続するだけで利用可能
- ミラーリング設定なしでも一部機能は利用可能

### 制御システムを構成するネットワークの可視化が可能

- 資産台帳の自動生成、多数の機器の属性、役割、通信状況を俯瞰的に可視化​
- セキュリティ強化すべき端末や通信箇所を明確化​
- 任意の2つ期間の資産台帳、通信状況の差分を可視化し、意図しない機器接続や設定変更を把握可能​

### 独自技術の実装により今まで以上に高い精度でセキュリティリスクを可視化​

- 定常時とは異なる振る舞いを検知することで、インシデントにつながる事象を把握可能
- 大規模ネットワークの通信解析で培ったNTTの技術を応用

## 紹介記事

- [制御システムのセキュリティと対策技術OsecTのご紹介（前編）](https://engineers.ntt.com/entry/2021/07/27/112539)
- [制御システムのセキュリティと対策技術OsecTのご紹介（後編）](https://engineers.ntt.com/entry/2021/08/02/113151)

## 実証実験

OsecTの機能をSaaSとして提供する実証実験を実施中です。詳細は[ニュースリリース](https://www.ntt.com/about-us/press-releases/news/article/2021/0524.html)をご覧ください。

実証実験で使用するOsecTセンサーの[仕様](osect_sensor/SPECIFICATION.md)と[ソースコード](osect_sensor/)を公開しています。
