# ネットワーク診断ツール

自宅回線のボトルネックを推測ではなく実測で特定するためのツール。CLI と GUI の2本立て。Python製、Windows向け。

このリポジトリはソースコードのみを公開しています。`python build.py` で `network_diag.exe` / `network_diag_gui.exe` を各自ビルドしてください(依存: Python 3、`pip install pyinstaller` ほか各タブが使うライブラリ)。

## 使い方

```
network_diag.exe <ラベル>      # フル診断を実行し results/<ラベル>_<日時>.json に保存
network_diag.exe --selftest    # パーサーの自己テストのみ（測定しない）
network_diag_gui.exe           # GUI（20ページ）
```

ラベルは前後比較の目印。対策を打つ前に `before`、打った後に `after_5ghz` のように付けて実行し、
GUIの「レポート」ページで2つ選ぶと差分表になる（古い方がA、新しい方がB）。

## GUIのページ

| ページ | 何を見るか |
|---|---|
| ダッシュボード | 現在の遅延・損失、品質グレード、接続方式、測定の鮮度、対策の上位3件を1画面に集約 |
| Ping | 遅延とパケットロスのリアルタイム推移 |
| 通信量 | NIC単位の送受信レート |
| フル診断 | CLIと同じ16項目を実行し、A〜Fの品質グレードを出す |
| 前後比較 | 保存済みJSONの2件比較 |
| 常時監視 | 複数ホストを継続ping。断とRTT急増をイベントとして記録 |
| 経路監視 | 各ホップのRTTを継続測定。どのホップで劣化しているか |
| LAN機器 | 同一セグメントのARP/pingスキャンとベンダー判定 |
| 構成図 | 経路とLAN機器から接続図を描く |
| DNS監査 | 応答時間・DNSSEC検証・NXDOMAIN改変・DoH/DoT到達性 |
| ポート | STUNによるNAT種別判定、UPnP/NAT-PMP、ポート開放確認 |
| 経路地図 | traceroute の各ホップを地図上に置く |
| 外部から測定 | RIPE Atlas の公開プローブから自ISPへのRTTを見る |
| 帯域/VPN | 帯域の時系列、仮想NIC・プロキシ・VPNの検出 |
| サービス | 主要サービス22件へのTCP接続RTTと外れ値検出 |
| トレンド | 時間帯別の速度・遅延を長期記録 |
| Windows設定 | TCP設定・NICの省電力・MTU・PMTUD・ドライバ更新の有無 |
| IPv6監査 | IPv6の経路MTU・プライバシー拡張・EUI-64の有無 |
| レポート | 結果をHTML/Markdownに書き出す。2件選ぶと前後比較 |
| 総合診断 | 全ページの結果を突き合わせて対策を優先度順に並べる |

細かい調整は右上の「⚙ 設定」（別ウィンドウ、11セクション）。値は `settings.json` に保存される。

## 無人で長期記録する

トレンドはGUIを開き続ける必要がある。放置で記録したいならタスクスケジューラでCLIを回す方が楽。
1日1回 4:00 に実行する例（動作確認済み）:

```
schtasks /create /tn "NetDiag" /tr "\"C:\path\to\network_diag.exe\" scheduled" /sc daily /st 04:00 /f
schtasks /delete /tn "NetDiag" /f     # やめるとき
```

results/ に溜まったJSONは「レポート」ページから任意の2件を比較できる。

## ビルド

```
python build.py
```

タブは GUI から動的importされるので PyInstaller が自動検出できない。build.py が
`network_diag_gui.py` からタブ一覧を読んで `--hidden-import` を組み立てる（手書きしない）。

## 開発時の注意

- **Windowsのコンソール出力は文字コードが混在する。** `netsh` は UTF-8、
  `ping`/`tracert`/`arp`/`netstat`/PowerShell は cp932。`nd.run()` の `encoding` で指定する。
- **保存先のパスは `settings_store.app_dir()` を使う。** PyInstaller onefile では
  `Path(__file__).parent` が終了時に消える一時フォルダを指すため、exe版だけ保存されなくなる。
- **設定項目を追加したら、必ずどこかで読む。** `python settings_store.py` が
  「誰にも読まれていない設定」を検出して落ちる。
- 各モジュールは `python <名前>.py --selftest` で単体テストできる。

## ライセンス

MIT License. 詳細は [LICENSE](LICENSE) を参照。
