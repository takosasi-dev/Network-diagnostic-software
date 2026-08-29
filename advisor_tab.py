"""総合診断・対処提案タブ。

各タブが results/ に吐いた保存済みJSONを横断的に読んで、「効果の大きい順に並んだ対処リスト」を出す。

設計方針(最重要): 断定しない。
    このツールでは過去に3回、早合点による誤診断が起きている。
      1. ルーターの認証レルム文字列から機器メーカーを推定 → 別メーカーだった
      2. 上り速度の落ち込みを機器故障と結論 → 実際は無線の周波数帯が原因だった
      3. STUNの外部ポートが3つとも違う → Symmetric NAT と判定 → 実際は測定側が
         送信元ポートを毎回変えていただけで Cone NAT だった
    そこで本モジュールは、
      - 提案ごとに確信度 (確定 / 強い / 弱い / 未検証) を持たせる
      - 根拠は必ず実測値そのもの(「〜のようだ」ではなく「TCP再送率 3.6%」)
      - 競合する説明があるものは「試す前に確認すべきこと」に明記する
      - 効果が無いと分かっている対策は「効果なし」として別に並べる
      - 根拠が足りないものは提案にせず「要追加測定」へ回し、どのタブで何を測るかを書く
    という形にしている。判定はすべて保存済みJSONから機械的に導くルールで、
    特定の環境の結論はハードコードしていない。
"""
import json
import threading
import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import ttk

import network_diag as nd
from settings_store import settings

# ---------- 確信度 ----------

CONF_CERTAIN = "確定"      # 測定値そのものが事実として問題を示しており、他の解釈の余地がない
CONF_STRONG = "強い"       # 複数の独立した測定が同じ方向を指す / 競合する説明はあるが可能性は低い
CONF_WEAK = "弱い"         # 測定は1つだけ、または因果の推定を1段挟んでいる
CONF_UNVERIFIED = "未検証"  # 測定手法自体に既知の落とし穴があり、そのままでは根拠にできない

CONF_TAG = {CONF_CERTAIN: "bad", CONF_STRONG: "warn", CONF_WEAK: "muted", CONF_UNVERIFIED: "muted"}
CONF_ORDER = {CONF_CERTAIN: 0, CONF_STRONG: 1, CONF_WEAK: 2, CONF_UNVERIFIED: 3}


# ---------- 保存済み結果の収集 ----------

# 種類 -> (globパターン, 表示名, JSONLか)
KINDS = {
    "full": (None, "フル診断", False),  # nd.list_result_files() で拾う
    "dnsaudit": ("dnsaudit_*.json", "DNS監査", False),
    "lanscan": ("lanscan_*.json", "LAN機器", False),
    "pathmon": ("pathmon_*.json", "経路監視", False),
    "services": ("services_*.json", "サービス到達性", False),
    "tuning": ("tuning_*.json", "Windows設定", False),
    "geomap": ("geomap_*.json", "経路地図", False),
    "trend": ("trend.jsonl", "時間帯トレンド", True),
    "watchdog": ("watchdog_*.jsonl", "常時監視", True),
}

# その種類が無いとき、どのタブで測れば埋まるか
KIND_TAB = {
    "full": "フル診断", "dnsaudit": "DNS監査", "lanscan": "LAN機器", "pathmon": "経路監視",
    "services": "サービス", "tuning": "Windows設定", "geomap": "経路地図",
    "trend": "トレンド", "watchdog": "常時監視",
}


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_jsonl(path):
    """1行1レコード。壊れた行は黙って捨てる(trend_tab.load_records と同じ方針)。"""
    out = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def collect(results_dir=None):
    """種類ごとに「最新の1件」を集める。無い種類は None のまま返す(落ちない)。"""
    root = Path(results_dir) if results_dir else nd.RESULTS_DIR
    sources = {}
    for kind, (pattern, _label, is_jsonl) in KINDS.items():
        try:
            if kind == "full":
                files = nd.list_result_files() if results_dir is None else \
                    sorted([p for p in root.glob("*.json")
                            if not p.name.startswith(nd.NON_DIAGNOSTIC_PREFIXES)],
                           key=lambda p: p.stat().st_mtime, reverse=True)
            else:
                files = sorted(root.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            files = []
        if not files:
            sources[kind] = None
            continue
        path = files[0]
        data = _read_jsonl(path) if is_jsonl else _read_json(path)
        if data is None or (is_jsonl and not data):
            sources[kind] = None
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            mtime = None
        stamp = data.get("timestamp") if isinstance(data, dict) else None
        sources[kind] = {"path": path, "name": path.name, "mtime": mtime,
                         "timestamp": stamp, "data": data}
    return sources


# ---------- 値の取り出し ----------

def _num(obj, *keys):
    """入れ子から数値を取り出す。キーが無い / {"error": ...} / bool なら None。"""
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
    if isinstance(obj, bool) or not isinstance(obj, (int, float)):
        return None
    return float(obj)


def _get(obj, *keys, default=None):
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k)
    return default if obj is None else obj


def _sec(source, key, default=None):
    """source(collectの戻り) の data から1セクション。{"error":...} でも dict のまま返す。"""
    if not source or not isinstance(source.get("data"), dict):
        return default if default is not None else {}
    v = source["data"].get(key)
    return v if isinstance(v, dict) else (default if default is not None else {})


def _when(source):
    if not source:
        return "-"
    stamp = source.get("timestamp")
    if isinstance(stamp, str) and stamp:
        return stamp.replace("T", " ")
    return source["mtime"].strftime("%Y-%m-%d %H:%M") if source.get("mtime") else "-"


def _origin(source):
    return f"{source['name']} ({_when(source)})" if source else "-"


def _fmt(v, digits=1):
    if v is None:
        return "-"
    return f"{v:.{digits}f}".rstrip("0").rstrip(".") if digits else f"{v:.0f}"


# ---------- 提案の器 ----------

def _advice(priority, title, confidence, evidence, steps, expect, origin, check_first=None):
    return {"priority": priority, "title": title, "confidence": confidence,
            "evidence": list(evidence), "check_first": list(check_first or []),
            "steps": list(steps), "expect": expect, "source": origin}


def _no_effect(title, reason, evidence, origin):
    return {"title": title, "reason": reason, "evidence": list(evidence), "source": origin}


def _more(title, tab, what, why):
    return {"title": title, "tab": tab, "what": what, "why": why}


# ---------- 評価本体 ----------

def evaluate(sources, contract_mbps=None):
    """収集済みデータ -> {"advice": [...], "no_effect": [...], "more": [...], ...}

    提案は priority 降順。priority は「効いたときの体感の大きさ」で手で振った目安値。
    """
    if contract_mbps is None:
        contract_mbps = settings.get("general.contract_mbps") or 1000
    advice, no_effect, more, notes = [], [], [], []

    full = sources.get("full")
    fdata = full["data"] if full and isinstance(full.get("data"), dict) else {}
    src_full = _origin(full)

    grade = None
    if fdata:
        try:
            grade = nd.grade_connection(fdata, contract_mbps=contract_mbps)
        except Exception as e:            # 古い形式で採点側が落ちても評価は続ける
            notes.append(f"グレード計算に失敗: {e}")
    else:
        more.append(_more("フル診断の結果がまだ無い", KIND_TAB["full"],
                          "「フル診断」タブで一通り測定して保存する",
                          "速度・遅延・損失・MTU・NAT の判定はすべてこの結果を根拠にしている"))

    # ---- 1. 速度(契約比) ----
    down = _num(fdata, "throughput", "parallel6", "mbps")
    if down is None:
        down = _num(fdata, "throughput", "single", "mbps")
    up = _num(fdata, "upload", "parallel6", "mbps")
    if up is None:
        up = _num(fdata, "upload", "single", "mbps")
    links = _get(fdata, "link_stats", "link", default=[]) or []
    link_speed = (links[0] or {}).get("LinkSpeed") if links and isinstance(links[0], dict) else None

    down_pct = down / contract_mbps * 100 if down is not None else None
    up_pct = up / contract_mbps * 100 if up is not None else None

    if down_pct is not None and down_pct < 70:
        ev = [f"下り {down:.0f} Mbps / 契約 {contract_mbps} Mbps (達成率 {down_pct:.0f}%)"]
        if up is not None:
            ev.append(f"上り {up:.0f} Mbps (達成率 {up_pct:.0f}%)")
        if link_speed:
            ev.append(f"PCのリンク速度 {link_speed}")
        rtt = _num(fdata, "latency", "1.1.1.1", "avg_ms")
        if rtt is not None:
            ev.append(f"遅延は {rtt:.0f} ms と正常 — 距離や輻輳ではなく区間の帯域が疑わしい"
                      if rtt <= 20 else f"遅延 {rtt:.0f} ms")
        advice.append(_advice(
            95 if down_pct < 40 else 70,
            f"速度が契約の {down_pct:.0f}% しか出ていない — どの区間で落ちているか切り分ける",
            CONF_CERTAIN, ev,
            ["PC をゲートウェイに有線で直結した状態で同じ測定をする(改善すれば途中の機器が原因)",
             "経路上の機器が無線でつながっている場合、5GHz帯に固定して再測定する",
             "各機器のWAN/LANポートのリンク速度を確認する(1台でも100Mbpsなら全体がそこで頭打ち)",
             "時間帯を変えて2回以上測り、測定サーバ側の混雑でないことを確かめる"],
            f"区間を特定できれば、その区間の改善で下りが最大 {contract_mbps} Mbps 級まで伸びる余地がある"
            f"(現状 {down:.0f} Mbps)",
            src_full,
            check_first=[
                "測定サーバ側の混雑ではないか(1回の測定だけで結論を出さない)",
                f"PCのリンク速度が契約速度以上か{'(現在 ' + str(link_speed) + ')' if link_speed else ''}"
                " — ここが上限なら回線側をいくら直しても伸びない",
                "経路に無線区間がある場合、2.4GHz帯につながっていないか。"
                "2.4GHzは5GHzの数分の一しか出ず、機器の故障と誤診しやすい",
            ]))
    elif down_pct is not None:
        no_effect.append(_no_effect(
            "回線の乗り換え・プラン変更で速度を上げる",
            f"下りは契約の {down_pct:.0f}% 出ており、契約帯域を使い切れている。"
            "上限を上げても実効速度は伸びにくい",
            [f"下り {down:.0f} Mbps / 契約 {contract_mbps} Mbps"], src_full))

    # 上りだけが極端に悪い場合は別項目。ただし原因の断定はしない(過去に無線帯域を故障と誤診)
    if down_pct is not None and up_pct is not None and up_pct < down_pct * 0.6 and up_pct < 50:
        advice.append(_advice(
            65, "上りだけが下りに比べて極端に低い",
            CONF_WEAK,
            [f"上り {up:.0f} Mbps ({up_pct:.0f}%) に対し 下り {down:.0f} Mbps ({down_pct:.0f}%)",
             f"上り/下り比 {up / down * 100:.0f}%"],
            ["経路に無線区間がある場合、まず5GHz帯につながっているか確認してから測り直す",
             "有線直結で上りだけ測って、同じ差が出るか見る",
             "上り方向のQoS/帯域制限がルーターに入っていないか確認する"],
            "上りが下りと同水準まで戻れば、アップロード・ビデオ会議・クラウド同期が改善する",
            src_full,
            check_first=["上下非対称は無線の帯域・電波状況でも簡単に起きる。"
                         "機器の故障と決めつける前に、必ず有線と5GHzの両方で測り直すこと"]))

    # ---- 2. 負荷時のパケット損失 ----
    idle_loss = _num(fdata, "bufferbloat", "idle_latency", "loss_pct")
    load_loss = _num(fdata, "bufferbloat", "loaded_latency", "loss_pct")
    idle_ms = _num(fdata, "bufferbloat", "idle_latency", "avg_ms")
    load_ms = _num(fdata, "bufferbloat", "loaded_latency", "avg_ms")
    bloat_pct = _num(fdata, "bufferbloat", "increase_pct")

    if load_loss is not None and load_loss >= 5:
        ev = [f"負荷時のパケット損失 {load_loss:.0f}%"
              + (f" (アイドル時 {idle_loss:.0f}%)" if idle_loss is not None else "")]
        if idle_ms is not None and load_ms is not None:
            ev.append(f"RTT アイドル {idle_ms:.0f} ms → 負荷時 {load_ms:.0f} ms")
        conf = CONF_STRONG if (idle_loss is not None and idle_loss <= 1) else CONF_WEAK
        advice.append(_advice(
            90, f"混雑時にパケットが {load_loss:.0f}% 落ちている", conf, ev,
            ["ルーターの QoS / SQM (スマートキュー) を有効にする",
             "上り・下りの帯域上限を実測値の 85〜90% に設定してキューを手前に持ってくる",
             "経路上の機器を1台ずつ外して同じ負荷測定を行い、損失が出る区間を特定する"],
            "損失が1%未満まで下がれば、ダウンロード中の通話・ゲーム・他端末のもたつきが解消する",
            src_full,
            check_first=[
                "ICMP(ping)は輻輳時に機器側で優先度を下げられることがあり、"
                "実データの損失率とは一致しない場合がある。TCP再送率と併せて見ること",
                f"アイドル時の損失が {(_fmt(idle_loss, 0) + '%') if idle_loss is not None else '未測定'}"
                " であること(アイドル時から落ちているなら回線そのものの問題)",
            ]))

    # ---- 3. バッファブロート ----
    if bloat_pct is not None and bloat_pct >= 75:
        ev = [f"負荷時の遅延増加 +{bloat_pct:.0f}%"]
        if idle_ms is not None and load_ms is not None:
            ev.append(f"{idle_ms:.0f} ms → {load_ms:.0f} ms")
        rpm = _num(fdata, "bufferbloat", "rpm_approx")
        if rpm is not None:
            ev.append(f"簡易RPM近似値 {rpm:.0f}")
        advice.append(_advice(
            55 if bloat_pct >= 150 else 40,
            f"バッファブロート: 負荷をかけると遅延が {bloat_pct:.0f}% 増える",
            CONF_CERTAIN if bloat_pct >= 150 else CONF_STRONG, ev,
            ["ルーターで SQM (fq_codel / CAKE) を有効にする",
             "有効化できない機種なら、上り帯域を実測の 85〜90% に絞るだけでも効果がある"],
            f"遅延増加が +25% 以下になれば、通信中でも {idle_ms:.0f} ms 前後の応答を保てる"
            if idle_ms is not None else "遅延増加が +25% 以下になれば通信中の応答性が安定する",
            src_full,
            check_first=["上の『混雑時のパケット損失』と原因が同じ(上流機器のキュー)である可能性が高い。"
                         "SQM を入れるなら両方まとめて改善するか確認すること"]
            if load_loss is not None and load_loss >= 5 else None))
    elif bloat_pct is not None:
        no_effect.append(_no_effect(
            "QoS / SQM を入れて遅延の跳ね上がりを抑える",
            f"負荷時の遅延増加は +{bloat_pct:.0f}% で、既に許容範囲に収まっている",
            [f"アイドル {_fmt(idle_ms, 0)} ms → 負荷時 {_fmt(load_ms, 0)} ms"], src_full))

    # ---- 4. TCP再送率 ----
    retrans = _num(fdata, "link_stats", "tcp_retransmit_pct")
    if retrans is not None and retrans >= 1:
        sent = _num(fdata, "link_stats", "tcp_segments_sent")
        rex = _num(fdata, "link_stats", "tcp_segments_retransmitted")
        ev = [f"TCP再送率 {retrans:.3f}% (健全な回線は通常1%未満)"]
        if sent and rex:
            ev.append(f"再送 {rex:,.0f} / 送信 {sent:,.0f} セグメント")
        adapters = _get(fdata, "link_stats", "adapters", default=[]) or []
        for a in adapters[:2]:
            if isinstance(a, dict) and a.get("ReceivedDiscardedPackets"):
                ev.append(f"{a.get('Name', 'NIC')}: 受信破棄 {a['ReceivedDiscardedPackets']:,} / "
                          f"受信エラー {a.get('ReceivedPacketErrors', 0):,}")
        advice.append(_advice(
            80 if retrans >= 3 else 35,
            f"TCP再送率が {retrans:.1f}% と高い — 物理層かどこかの区間で落ちている",
            CONF_STRONG if retrans >= 3 else CONF_WEAK, ev,
            ["有線区間の LANケーブルとポートを別のものに替えて再測定する",
             "経路に無線区間があれば、そこだけ有線に置き換えて再測定する",
             "NIC のドライバを更新し、省電力設定(自動速度低下)を無効にする"],
            "1%未満まで下がれば、再送に費やしていた分だけ実効スループットが伸びる",
            src_full,
            check_first=[
                "この値は Windows 起動からの累計。過去の一時的な障害を引きずっている可能性がある。"
                "PC再起動後に測り直して同水準なら確定と見てよい",
                "受信破棄/受信エラーが 0 なら PC の NIC 側ではなく、その先の区間が疑わしい",
            ]))
    elif retrans is not None:
        no_effect.append(_no_effect(
            "NIC のドライバ更新やケーブル交換で安定性を上げる",
            f"TCP再送率は {retrans:.3f}% で健全値(1%未満)。物理層に問題は見えていない",
            [f"TCP再送率 {retrans:.3f}%"], src_full))

    # ---- 5. 遅延 / ジッター / MOS ----
    rtt = _num(fdata, "latency", "1.1.1.1", "avg_ms")
    rtt2 = _num(fdata, "latency", "8.8.8.8", "avg_ms")
    gw_rtt = _num(fdata, "latency", "gateway", "avg_ms")
    jitter = _num(fdata, "jitter", "jitter_ms")
    mos = _num(fdata, "jitter", "mos")

    if rtt is not None and rtt > 40:
        advice.append(_advice(
            60, f"遅延が {rtt:.0f} ms と大きい", CONF_STRONG,
            [f"1.1.1.1 まで {rtt:.0f} ms" + (f" / 8.8.8.8 まで {rtt2:.0f} ms" if rtt2 else ""),
             f"ゲートウェイまで {gw_rtt:.0f} ms" if gw_rtt is not None else "ゲートウェイ遅延は未測定"],
            ["経路監視タブで hop ごとの遅延を見て、どのホップで跳ねているか特定する",
             "ゲートウェイまでの遅延が大きい場合は宅内(機器・無線区間)、"
             "小さい場合はISP側かその先が原因"],
            "20 ms 台まで下がれば、ゲームの反応・ページの表示開始が体感で変わる", src_full,
            check_first=["物理的な距離で決まる下限がある。ISPの収容局や測定先が遠い場合、"
                         "宅内をいくら直しても縮まらない"]))
    elif rtt is not None and jitter is not None and mos is not None \
            and rtt <= 20 and jitter <= 5 and mos >= 4.0:
        no_effect.append(_no_effect(
            "DNSサーバ変更・「ゲーミング」設定・QoS で ping を下げる",
            f"RTT {rtt:.0f} ms / ジッター {jitter:.2f} ms / MOS {mos} は既に良好。"
            "ここから先は物理距離で決まる領域で、設定では動かない",
            [f"RTT {rtt:.0f} ms", f"ジッター {jitter:.2f} ms", f"MOS {mos}"], src_full))

    # ---- 6. 経路MTU ----
    mtu = _num(fdata, "path_mtu", "mtu")
    mtu_note = _get(fdata, "path_mtu", "interpretation", default="")
    if mtu is None and fdata:
        more.append(_more("経路MTUが未測定", KIND_TAB["full"],
                          "フル診断を最新版で実行し直す(古い結果には path_mtu が無い)",
                          "MTU が分からないと、フラグメント由来の速度低下を切り分けられない"))
    elif mtu is not None and mtu < 1454:
        advice.append(_advice(
            45, f"経路MTUが {mtu:.0f} と小さい", CONF_STRONG,
            [f"経路MTU {mtu:.0f} バイト", f"判定: {mtu_note}" if mtu_note else ""],
            ["ルーターのWAN側MTUを経路MTUに合わせる",
             "PPPoE 接続なら IPoE (IPv4 over IPv6) が使えないか契約を確認する"],
            "無駄なフラグメントが消え、特に上りのスループットが改善することがある", src_full))
    elif mtu is not None:
        no_effect.append(_no_effect(
            "MTU / RWIN を手動で調整して速度を上げる",
            f"経路MTUは {mtu:.0f} で、この接続方式として整合が取れている。"
            "手動で下げるとむしろ効率が落ちる",
            [f"経路MTU {mtu:.0f}" + (f" — {mtu_note}" if mtu_note else "")], src_full))

    # ---- 7. NAT タイプ ----
    # 過去に「外部ポートが3つとも違う」を Symmetric NAT と誤判定した。実際は測定側が
    # 送信元ポートを毎回変えていただけだった。連番に近いポートはその副作用の典型なので、
    # 提案ではなく「要追加測定」に落とす。
    nat = _sec(full, "nat")
    nat_type = nat.get("nat_type") if isinstance(nat.get("nat_type"), str) else None
    ports = [p for p in (nat.get("external_ports") or []) if isinstance(p, int)]
    if nat_type and "Symmetric" in nat_type:
        spread = (max(ports) - min(ports)) if len(ports) >= 2 else None
        if spread is not None and len(set(ports)) > 1 and spread <= 16:
            more.append(_more(
                f"NATタイプの判定 ({nat_type.split('(')[0].strip()}) は測定側の副作用かもしれない",
                "ポート",
                "同一のローカル送信元ポートを使い回して複数のSTUNサーバへ問い合わせる。"
                "それでも外部ポートが揃わなければ Symmetric NAT で確定、揃えば Cone NAT",
                f"観測された外部ポート {ports} は差がわずか {spread} の連番に近い並び。"
                "送信元ポートを毎回変えて測ると必ずこうなるため、Symmetric NAT の証拠にはならない"))
        else:
            advice.append(_advice(
                50, "NATが Symmetric 型 — P2P接続やゲームのマッチングで不利になる", CONF_WEAK,
                [f"判定: {nat_type}", f"観測された外部ポート {ports}" if ports else ""],
                ["ルーターの2重NATを解消する(ONU側かルーター側のどちらかをブリッジにする)",
                 "ゲーム機は UPnP かポート開放で明示的に外部ポートを固定する"],
                "Cone NAT になれば、P2P・ボイスチャット・対戦マッチングの成功率が上がる", src_full,
                check_first=["STUN測定は送信元ポートを固定していないと必ず Symmetric に見える。"
                             "ポートタブで送信元ポートを固定して測り直してから対処すること"]))
    elif nat_type:
        no_effect.append(_no_effect(
            "NATタイプを改善するためにルーターを買い替える / 2重NATを解消する",
            f"現在の判定は「{nat_type.split('(')[0].strip()}」で、P2Pやマッチングに不利な型ではない",
            [f"判定: {nat_type}"] + ([f"外部ポート {ports}"] if ports else []), src_full))

    # ---- 8. UPnP / NAT-PMP (ポートタブは結果をJSON保存しないため、常に未測定扱い) ----
    more.append(_more(
        "ポート開放 (UPnP IGD / NAT-PMP) の可否が保存されていない", "ポート",
        "「ポート」タブの UPnP / NAT-PMP 探索を実行する",
        "自動ポート開放が使えるかどうかで、P2P・ゲーム・サーバ公開の対処方法が変わる。"
        "このタブが読める形で保存されないため、毎回目視で確認する必要がある"))

    # ---- 9. IPv6 ----
    ipv6 = _sec(full, "ipv6")
    if fdata and isinstance(ipv6, dict) and "has_global_address" in ipv6:
        if ipv6.get("has_global_address") and not ipv6.get("egress_reachable"):
            advice.append(_advice(
                50, "IPv6アドレスは持っているのに外へ出られていない", CONF_CERTAIN,
                [f"グローバルIPv6アドレス {len(ipv6.get('global_addresses') or [])} 個",
                 f"デフォルトルート: {'あり' if ipv6.get('has_default_route') else 'なし'}",
                 "IPv6での外部到達: 不可"],
                ["ルーターのIPv6パススルー/ブリッジ設定を確認する",
                 "Windows のファイアウォールとIPv6の優先設定を確認する"],
                "IPv6が通れば IPoE 経由の混雑回避が効き、夜間の速度低下が緩和されることがある",
                src_full))
        elif ipv6.get("egress_reachable"):
            v4 = _num(fdata, "ip_version_compare", "ipv4", "mbps")
            v6 = _num(fdata, "ip_version_compare", "ipv6", "mbps")
            if v4 and v6 and v6 < v4 * 0.7:
                advice.append(_advice(
                    30, "IPv6経由のほうが IPv4経由より遅い", CONF_WEAK,
                    [f"IPv4経由 {v4:.0f} Mbps / IPv6経由 {v6:.0f} Mbps"],
                    ["測定サーバ側のIPv6経路の問題である可能性が高いので、別ホストでも比較する"],
                    "原因がISP側なら申告材料になる。宅内側なら設定で戻せる", src_full,
                    check_first=["1つの測定先だけの比較では、その先のCDNのIPv6対応状況を見ているだけ"
                                 "の可能性がある"]))

    # ---- 10. DNS (dnsaudit) ----
    dnsaudit = sources.get("dnsaudit")
    if dnsaudit:
        src_dns = _origin(dnsaudit)
        hijack = [r for r in (_get(dnsaudit["data"], "nxdomain", "rows", default=[]) or [])
                  if isinstance(r, dict) and r.get("tag") == "bad"]
        if hijack:
            advice.append(_advice(
                85, "存在しないドメインに応答が返っている (DNSハイジャックの疑い)", CONF_CERTAIN,
                [f"{r.get('label', '?')}: {r.get('measured', '')} → {r.get('verdict', '')}"
                 for r in hijack[:4]],
                ["ルーターのDNS転送設定を確認し、ISPの広告挿入型リゾルバを使っていないか調べる",
                 "PC の DNS を 1.1.1.1 / 8.8.8.8 / 9.9.9.9 のいずれかに固定する"],
                "タイプミス時に広告ページへ飛ばされなくなり、名前解決の失敗が正しくエラーになる",
                src_dns))

        dnssec_rows = _get(dnsaudit["data"], "dnssec", "rows", default=[]) or []
        bad_dnssec = [r for r in dnssec_rows if isinstance(r, dict) and r.get("tag") in ("warn", "bad")]
        ok_dnssec = [r.get("label", "") for r in dnssec_rows
                     if isinstance(r, dict) and r.get("tag") == "good"]
        if bad_dnssec:
            using_router = any("ルーター" in (r.get("label") or "") for r in bad_dnssec)
            advice.append(_advice(
                32 if using_router else 20,
                f"DNSSEC 検証をしていないリゾルバがある ({len(bad_dnssec)} 件)", CONF_CERTAIN,
                [f"{r.get('label', '?')}: {r.get('measured', '')}" for r in bad_dnssec[:4]]
                + ([f"検証できているリゾルバ: {' / '.join(ok_dnssec)}"] if ok_dnssec else []),
                [f"PC またはルーターの DNS を {ok_dnssec[0]} など検証しているリゾルバに変更する"
                 if ok_dnssec else
                 "DNSSEC を検証するパブリックリゾルバ (1.1.1.1 / 8.8.8.8 / 9.9.9.9) に変更する",
                 "変更後に DNS監査タブを再実行し、AD ビットが立つことを確認する"],
                "偽装されたDNS応答を掴まされるリスクが下がる(体感速度は変わらない)", src_dns,
                check_first=["ルーターのDNSを変えると、ルーターが配っている宅内向けの名前解決"
                             "(機器名でのアクセス等)が使えなくなる場合がある",
                             "DNSSEC未検証そのものは『壊れている』わけではない。"
                             "速度や接続性の問題の原因ではないので、優先度は低い"]))

        # 速度目的のDNS変更は効くのか
        r_ms = _num(fdata, "dns", "router", "avg_ms")
        pub_ms = min([v for v in (_num(fdata, "dns", "1.1.1.1", "avg_ms"),
                                  _num(fdata, "dns", "8.8.8.8", "avg_ms")) if v is not None] or [None])
        if r_ms is not None and pub_ms is not None and r_ms - pub_ms < 15:
            no_effect.append(_no_effect(
                "体感を上げる目的で DNS サーバを変更する",
                f"ルーター {r_ms:.1f} ms とパブリック {pub_ms:.1f} ms の差は {r_ms - pub_ms:+.1f} ms しかなく、"
                "ページ表示の体感は変わらない(DNSSEC目的の変更は別項目)",
                [f"ルーター {r_ms:.1f} ms", f"最速のパブリックリゾルバ {pub_ms:.1f} ms"], src_full))
    else:
        more.append(_more("DNSの健全性が未測定", KIND_TAB["dnsaudit"],
                          "「DNS監査」タブを実行して保存する",
                          "DNSハイジャック・DNSSEC検証の有無・暗号化DNSの可否はここでしか分からない"))

    # ---- 11. Windows 設定 (tuning) ----
    tuning = sources.get("tuning")
    if tuning:
        src_tuning = _origin(tuning)
        findings = [f for f in (_get(tuning["data"], "findings", default=[]) or [])
                    if isinstance(f, dict)]
        actions = [f for f in findings if f.get("sev") == 0]
        for f in actions[:5]:
            advice.append(_advice(
                48, f"Windows設定: {f.get('item', '?')}", CONF_CERTAIN,
                [f"現在値: {f.get('current', '-')}", f"推奨値: {f.get('recommend', '-')}",
                 f.get("why", "")],
                ([f"管理者権限のコマンドプロンプトで実行: {f['cmd']}"] if f.get("cmd") else [])
                + ["変更後に必ずフル診断を測り直し、実際に改善したか数値で確認する"],
                "OS 側のボトルネックが外れる。回線側の問題には効かない点に注意", src_tuning,
                check_first=["OS設定の変更は回線そのものの問題を解決しない。"
                             "速度不足が別項目で出ている場合は、そちらを先に切り分けること"]))
        if not actions:
            no_effect.append(_no_effect(
                "レジストリや netsh で Windows のTCP設定をチューニングする",
                _get(tuning["data"], "summary", default="要対処の項目は検出されていない"),
                [f"検査項目 {len(findings)} 件中、要対処 0 件"], src_tuning))
    else:
        more.append(_more("Windows 側の設定が未検査", KIND_TAB["tuning"],
                          "「Windows設定」タブを実行して保存する",
                          "RSS・自動チューニング・輻輳制御・オフロード・受信バッファの問題は"
                          "ここでしか分からない"))

    # ---- 12. サービス到達性 ----
    services = sources.get("services")
    if services:
        src_svc = _origin(services)
        rows = [r for r in (_get(services["data"], "services", default=[]) or []) if isinstance(r, dict)]
        overall = _num(services["data"], "overall_median_ms")
        outliers = _get(services["data"], "outliers", default=[]) or []
        slow = [r for r in rows if isinstance(r.get("median_ms"), (int, float))
                and (r["name"] in outliers or (overall and r["median_ms"] > max(overall * 4, 80)))]
        slow.sort(key=lambda r: -r["median_ms"])
        if slow:
            advice.append(_advice(
                18, f"特定のサービスだけ応答が遅い ({len(slow)} 件)", CONF_WEAK,
                [f"{r.get('name', '?')} ({r.get('host', '')}): {r['median_ms']:.0f} ms"
                 f"{' / ' + r['org'] if r.get('org') else ''}" for r in slow[:5]]
                + ([f"全サービスの中央値 {overall:.0f} ms"] if overall else []),
                ["経路地図タブでそのホストへの経路を見て、実際に遠い拠点に繋がっていないか確認する",
                 "遠い拠点が返ってきているだけなら回線側の対処は無い(DNSを変えると近いPoPに"
                 "変わることがまれにある)"],
                "回線側が原因なら改善するが、相手側のPoP配置が原因なら変わらない", src_svc,
                check_first=[f"他のサービスの中央値が {overall:.0f} ms なら回線側は正常"
                             if overall else "他のサービスの中央値と比べること",
                             "1サービスだけの遅さは、たいてい相手側の拠点が遠いだけ。"
                             "回線の異常と結びつける前に経路を見ること"]))
        elif rows:
            no_effect.append(_no_effect(
                "特定サービスが遅いのを回線側の設定で直す",
                f"測定した {len(rows)} サービスに突出した外れ値は無い",
                [f"全サービスの中央値 {overall:.0f} ms" if overall else f"{len(rows)} サービスを測定"],
                src_svc))
    else:
        more.append(_more("主要サービスへの到達性が未測定", KIND_TAB["services"],
                          "「サービス」タブを実行して保存する",
                          "特定サービスだけ遅いのか、回線全体が遅いのかを切り分ける材料になる"))

    # ---- 13. 経路監視 (pathmon) ----
    pathmon = sources.get("pathmon")
    if pathmon:
        src_path = _origin(pathmon)
        hops = [h for h in (_get(pathmon["data"], "hops", default=[]) or []) if isinstance(h, dict)]
        lossy = [h for h in hops if isinstance(h.get("loss_pct"), (int, float)) and h["loss_pct"] >= 5]
        last = hops[-1] if hops else None
        last_loss = last.get("loss_pct") if isinstance(last, dict) else None
        if lossy and isinstance(last_loss, (int, float)) and last_loss >= 5:
            advice.append(_advice(
                75, f"経路上で継続的にパケットが落ちている (最終ホップで {last_loss:.0f}%)",
                CONF_STRONG,
                [f"hop {h['hop']} {h.get('ip') or '?'}: 損失 {h['loss_pct']:.0f}% "
                 f"({h.get('recv', '?')}/{h.get('sent', '?')})" for h in lossy[:5]]
                + [f"サイクル数 {_get(pathmon['data'], 'cycles', default='-')}"],
                ["損失が始まる最初のホップの手前までが自分の管理範囲。"
                 "宅内なら機器・ケーブルを、ISP側ならその区間を添えて申告する",
                 "同じ測定を時間帯を変えて繰り返し、恒常的か一時的かを見る"],
                "損失が消えれば、再送によるスループット低下と突発的なラグが解消する", src_path,
                check_first=["中間ホップだけの損失は ICMP のレート制限で普通に起きる。"
                             "最終ホップまで損失が続いている場合だけ本物と考えること"]))
        elif lossy:
            no_effect.append(_no_effect(
                "経路の途中で損失が出ているホップを ISP に申告する",
                f"損失は中間ホップ {len(lossy)} 件のみで、最終ホップは "
                f"{('損失 %.0f%%' % last_loss) if isinstance(last_loss, (int, float)) else '正常'}。"
                "中間ホップの ICMP 応答落ちは機器のレート制限で、通信品質とは関係がない",
                [f"hop {h['hop']} {h.get('ip') or '?'}: {h['loss_pct']:.0f}%" for h in lossy[:4]],
                src_path))
    else:
        more.append(_more("経路上のどこで落ちているかが未測定", KIND_TAB["pathmon"],
                          "「経路監視」タブで数分間流し続けて保存する",
                          "パケット損失や遅延の発生区間(宅内 / ISP / その先)を切り分けられる"))

    # ---- 14. 時間帯トレンド ----
    trend = sources.get("trend")
    min_samples = settings.get("trend.min_samples") or 3
    recs = trend["data"] if trend and isinstance(trend.get("data"), list) else []
    hourly = {}
    for r in recs:
        if not isinstance(r, dict):
            continue
        v = r.get("down_mbps")
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        h = r.get("hour")
        if not isinstance(h, int):
            try:
                h = datetime.fromisoformat(r["ts"]).hour
            except (KeyError, TypeError, ValueError):
                continue
        hourly.setdefault(h, []).append(float(v))
    usable = {h: vs for h, vs in hourly.items() if len(vs) >= min_samples}
    if len(usable) < 3:
        more.append(_more(
            "時間帯による変動が判定できない (データ不足)", KIND_TAB["trend"],
            f"「トレンド」タブの自動計測を有効にして、1時間帯あたり {min_samples} 件以上、"
            "最低3つの時間帯にまたがるまでためる",
            f"現在 {len(recs)} 件 / 条件を満たす時間帯 {len(usable)} 個。"
            "夜だけ遅いのか常に遅いのかで、対処(ISPへの申告か宅内改善か)が正反対になる"))
    else:
        meds = {h: sorted(vs)[len(vs) // 2] for h, vs in usable.items()}
        best_h = max(meds, key=meds.get)
        worst_h = min(meds, key=meds.get)
        if meds[best_h] and meds[worst_h] < meds[best_h] * 0.65:
            advice.append(_advice(
                62, f"時間帯によって速度が大きく変わる ({worst_h}時台が最も遅い)", CONF_STRONG,
                [f"{worst_h}時台 中央値 {meds[worst_h]:.0f} Mbps ({len(usable[worst_h])} 件)",
                 f"{best_h}時台 中央値 {meds[best_h]:.0f} Mbps ({len(usable[best_h])} 件)",
                 f"比 {meds[worst_h] / meds[best_h] * 100:.0f}%"],
                ["宅内機器を全部止めた状態で遅い時間帯に測り直し、宅外(ISP側の輻輳)か宅内かを分ける",
                 "ISP側の輻輳が疑わしければ、IPoE / IPv6接続に切り替えられないか契約を確認する",
                 "時間帯と実測値を添えて ISP に申告する"],
                f"混雑時間帯が {best_h}時台と同水準になれば、実効速度が "
                f"{meds[best_h] / max(meds[worst_h], 0.1):.1f} 倍になる", _origin(trend),
                check_first=["自分の家の他端末が使っていた時間帯ではないか。"
                             "測定中の宅内トラフィックは同じ形で現れる"]))
        else:
            no_effect.append(_no_effect(
                "混雑時間帯を避けて使う / ISP に輻輳を申告する",
                f"計測できている時間帯の中では速度差が小さい"
                f"({worst_h}時台 {meds[worst_h]:.0f} Mbps 〜 {best_h}時台 {meds[best_h]:.0f} Mbps)",
                [f"{len(usable)} 時間帯 / 全 {len(recs)} 件"], _origin(trend)))

    # ---- 15. 常時監視のイベント ----
    watchdog = sources.get("watchdog")
    events = watchdog["data"] if watchdog and isinstance(watchdog.get("data"), list) else []
    if watchdog:
        counts = {}
        for e in events:
            if isinstance(e, dict):
                counts[e.get("type", "?")] = counts.get(e.get("type", "?"), 0) + 1
        downs = counts.get("切断", 0)
        spikes = counts.get("RTT急増", 0)
        if downs or spikes >= 5:
            recent = [e for e in events if isinstance(e, dict)][-4:]
            advice.append(_advice(
                88 if downs else 42,
                f"監視中に異常が記録されている (切断 {downs} 件 / RTT急増 {spikes} 件)",
                CONF_CERTAIN,
                [f"{k}: {v} 件" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
                + [f"最近: {e.get('time', '')} {e.get('target', '')} {e.get('type', '')} "
                   f"{e.get('detail', '')}" for e in recent],
                ["切断の対象がゲートウェイなら宅内、外部ホストだけなら宅外が原因",
                 "同じ時刻に他の機器も切れていたかを確認する",
                 "頻度と時刻を記録して ISP または機器メーカーに申告する"],
                "切断が消えれば、通話・ゲーム・ダウンロードの突然の中断が無くなる", _origin(watchdog),
                check_first=["監視対象がゲートウェイのみか外部ホストも含むかで、切り分けの意味が変わる。"
                             "対象欄を確認すること"]))
        else:
            no_effect.append(_no_effect(
                "頻繁な切断を疑って機器を交換する",
                f"記録されているイベントは {len(events)} 件で、切断は 0 件",
                [f"{k}: {v} 件" for k, v in counts.items()] or ["イベント記録なし"], _origin(watchdog)))
    else:
        more.append(_more("突発的な切断・遅延スパイクの有無が未記録", KIND_TAB["watchdog"],
                          "「常時監視」タブを起動したまま数時間〜1日流す",
                          "一瞬の切断は単発の測定には映らない。体感の「たまに止まる」を裏付けられる"))

    # ---- 古いデータへの注意 ----
    for kind, src in sources.items():
        if src and src.get("mtime") and datetime.now() - src["mtime"] > timedelta(days=7):
            notes.append(f"{KINDS[kind][1]} のデータが {(datetime.now() - src['mtime']).days} 日前"
                         f"のもの ({src['name']}) — 現状と食い違っている可能性がある")

    advice.sort(key=lambda a: (-a["priority"], CONF_ORDER.get(a["confidence"], 9), a["title"]))
    return {"advice": advice, "no_effect": no_effect, "more": more, "notes": notes,
            "grade": grade, "contract_mbps": contract_mbps,
            "generated": datetime.now().replace(microsecond=0).isoformat(sep=" "),
            "sources": [(KINDS[k][1], sources[k]["name"] if sources.get(k) else None,
                         _when(sources.get(k))) for k in KINDS]}


# ---------- Markdown 出力 ----------

def to_markdown(ev):
    L = ["# ネットワーク総合診断 — 対処提案", "", f"生成: {ev['generated']}",
         f"契約速度の設定値: {ev['contract_mbps']} Mbps", ""]
    g = ev.get("grade")
    if g:
        L += [f"総合グレード: **{g.get('grade')}** ({g.get('score')} 点)  ", f"{g.get('comment', '')}", ""]

    L += ["## 元になった測定", "", "| 種類 | ファイル | 計測日時 |", "|---|---|---|"]
    for label, name, when in ev["sources"]:
        L.append(f"| {label} | {name or '(無し)'} | {when} |")
    L.append("")

    if ev["notes"]:
        L += ["> [!warning] データの鮮度", ""] + [f"> - {n}" for n in ev["notes"]] + [""]

    L += ["## 対処提案 (効果の大きい順)", ""]
    if not ev["advice"]:
        L += ["特に対処が必要な問題は検出されませんでした。", ""]
    for i, a in enumerate(ev["advice"], 1):
        L += [f"### {i}. {a['title']}", "",
              f"**確信度: {a['confidence']}**  |  根拠データ: `{a['source']}`", "",
              "**根拠となった実測値**", ""]
        L += [f"- {e}" for e in a["evidence"] if e]
        if a["check_first"]:
            L += ["", "**試す前に確認すること**", ""] + [f"- {c}" for c in a["check_first"]]
        L += ["", "**手順**", ""] + [f"{n}. {s}" for n, s in enumerate(a["steps"], 1)]
        L += ["", f"**期待できる効果**: {a['expect']}", ""]

    L += ["## 効果が見込めない対策 (やらなくてよい)", ""]
    if not ev["no_effect"]:
        L += ["判定できたものはありません。", ""]
    for n in ev["no_effect"]:
        L += [f"### {n['title']}", "", f"{n['reason']}", ""] \
            + [f"- {e}" for e in n["evidence"] if e] + ["", f"根拠データ: `{n['source']}`", ""]

    L += ["## 要追加測定 (これを測れば確定できる)", ""]
    if not ev["more"]:
        L += ["不足している測定はありません。", ""]
    for m in ev["more"]:
        L += [f"### {m['title']}", "", f"- **どこで**: 「{m['tab']}」タブ",
              f"- **何を**: {m['what']}", f"- **なぜ**: {m['why']}", ""]

    L += ["---", "",
          "確信度の意味: **確定**=実測値そのものが問題を示している / "
          "**強い**=複数の測定が同じ方向を指す / **弱い**=推定を1段挟んでいる / "
          "**未検証**=測定手法に既知の落とし穴があり、そのままでは根拠にできない", ""]
    return "\n".join(L)


# ---------- タブ本体 ----------

SECTIONS = [("advice", "対処提案 (効果の大きい順)"),
            ("no_effect", "効果が見込めない対策"),
            ("more", "要追加測定")]


class AdvisorTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.result = None
        self._thread = None
        self._stop = threading.Event()

        top = ttk.Frame(parent)
        top.pack(fill="x", padx=8, pady=(8, 4))
        self.run_btn = ttk.Button(top, text="▶  再評価", style="Accent.TButton", command=self.start)
        self.run_btn.pack(side="left")
        self.export_btn = ttk.Button(top, text="Markdownで出力", command=self.export, state="disabled")
        self.export_btn.pack(side="left", padx=(6, 0))
        self.status = ttk.Label(top, text="保存済みの結果を読み込んでいます ...")
        self.status.pack(side="left", padx=(12, 0))

        self.summary = ttk.Label(parent, text="", wraplength=1100, justify="left")
        self.summary.pack(fill="x", padx=8, pady=(2, 0))
        self.origin_label = ttk.Label(parent, text="", wraplength=1100, justify="left")
        self.origin_label.pack(fill="x", padx=8, pady=(2, 6))

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.tree = ttk.Treeview(body, columns=("conf", "evid"), height=16)
        self.tree.heading("#0", text="提案 / 内訳")
        self.tree.heading("conf", text="確信度")
        self.tree.heading("evid", text="根拠となった実測値")
        self.tree.column("#0", width=520, stretch=True)
        self.tree.column("conf", width=80, anchor="center", stretch=False)
        self.tree.column("evid", width=520, stretch=True)
        vs = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        foot = ttk.Frame(parent)
        foot.pack(fill="x", padx=8, pady=(0, 8))
        self.detail = tk.Text(foot, height=11, wrap="word", relief="flat",
                              font=(ctx.font, 9), padx=8, pady=6)
        ds = ttk.Scrollbar(foot, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=ds.set, state="disabled")
        self.detail.pack(side="left", fill="both", expand=True)
        ds.pack(side="left", fill="y")

        self._nodes = {}
        self.on_theme_changed()
        self.start()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        for tag in ("good", "warn", "bad", "muted"):
            self.tree.tag_configure(tag, foreground=t[tag])
        self.tree.tag_configure("section", foreground=t["fg"])
        # sv_ttk が style map に -foreground を持っており、そのままだと行タグ色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる(pathmon_tab.py と同じ手当て)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.detail.configure(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"])
        for name, color in (("h", t["fg"]), ("good", t["good"]), ("warn", t["warn"]),
                            ("bad", t["bad"]), ("muted", t["muted"])):
            self.detail.tag_configure(name, foreground=color)
        self.summary.configure(foreground=t["fg"])
        self.origin_label.configure(foreground=t["muted"])
        self.status.configure(foreground=t["muted"])

    def _set_status(self, text, tone="muted"):
        self.status.configure(text=text, foreground=self.ctx.theme[tone])

    # ---- 実行 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.run_btn.configure(state="disabled")
        self._set_status("保存済みの結果を読み込んでいます ...")
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        try:
            ev = evaluate(collect())
            err = None
        except Exception as e:                     # 評価が落ちてもタブは生き残らせる
            ev, err = None, f"{type(e).__name__}: {e}"
        if self._stop.is_set():
            return
        try:
            self.ctx.root.after(0, self._render, ev, err)
        except (RuntimeError, tk.TclError):
            pass  # mainloop終了後/ウィンドウ破棄後に完了した場合。捨ててよい

    def _render(self, ev, err):
        self.run_btn.configure(state="normal")
        if err:
            self._set_status(f"評価に失敗しました — {err}", "bad")
            return
        self.result = ev
        self.export_btn.configure(state="normal")

        g = ev.get("grade") or {}
        if g.get("score") is not None:
            self.summary.configure(
                text=f"総合グレード {g.get('grade')} ({g.get('score')} 点 / 契約 {ev['contract_mbps']} Mbps)"
                     f"   {g.get('comment', '')}")
        else:
            self.summary.configure(text="フル診断の結果が無いため、総合グレードは算出できません")

        used = [f"{label}: {name} [{when}]" for label, name, when in ev["sources"] if name]
        missing = [label for label, name, _ in ev["sources"] if not name]
        text = "元データ  " + ("  /  ".join(used) if used else "(保存済みの結果がありません)")
        if missing:
            text += f"\n未取得: {' / '.join(missing)}"
        for n in ev["notes"]:
            text += f"\n⚠ {n}"
        self.origin_label.configure(text=text)

        self.tree.delete(*self.tree.get_children())
        self._nodes = {}
        for key, label in SECTIONS:
            items = ev[key]
            head = self.tree.insert("", "end", text=f"■ {label} ({len(items)} 件)",
                                    values=("", ""), open=True, tags=("section",))
            if not items:
                self.tree.insert(head, "end", text="  該当なし", values=("", ""), tags=("muted",))
            for i, item in enumerate(items, 1):
                node = self._insert_item(head, key, i, item)
                self._nodes[node] = (key, item)

        self._show_detail_text(
            "一覧の行を選ぶと、その項目の根拠・確認事項・手順をここに全文表示します。\n\n"
            "確信度の意味\n"
            "  確定    実測値そのものが問題を示しており、他の解釈の余地がない\n"
            "  強い    複数の測定が同じ方向を指す(競合する説明は確認事項に書いてあります)\n"
            "  弱い    測定は1つだけ、または因果の推定を1段挟んでいる\n"
            "  未検証  測定手法に既知の落とし穴があり、そのままでは根拠にできない"
            " → 「要追加測定」に回してあります\n")

        n_act = len(ev["advice"])
        self._set_status(
            f"対処提案 {n_act} 件 / 効果なし {len(ev['no_effect'])} 件 / 要追加測定 {len(ev['more'])} 件",
            "good" if n_act == 0 else ("bad" if any(a["priority"] >= 80 for a in ev["advice"]) else "warn"))

    def _insert_item(self, parent, key, i, item):
        if key == "advice":
            tag = CONF_TAG.get(item["confidence"], "muted")
            node = self.tree.insert(parent, "end", text=f"{i}. {item['title']}",
                                    values=(item["confidence"],
                                            item["evidence"][0] if item["evidence"] else ""),
                                    tags=(tag,))
            for e in item["evidence"][1:]:
                if e:
                    self.tree.insert(node, "end", text="", values=("", e), tags=("muted",))
            for c in item["check_first"]:
                self.tree.insert(node, "end", text=f"  ⚠ 確認: {c}", values=("", ""), tags=("warn",))
            for n, s in enumerate(item["steps"], 1):
                self.tree.insert(node, "end", text=f"  {n}) {s}", values=("", ""), tags=("good",))
            self.tree.insert(node, "end", text=f"  → 期待できる効果: {item['expect']}",
                             values=("", item["source"]), tags=("muted",))
            return node
        if key == "no_effect":
            node = self.tree.insert(parent, "end", text=f"{i}. {item['title']}",
                                    values=("効果なし", item["reason"]), tags=("muted",))
            for e in item["evidence"]:
                if e:
                    self.tree.insert(node, "end", text="", values=("", e), tags=("muted",))
            return node
        node = self.tree.insert(parent, "end", text=f"{i}. {item['title']}",
                                values=(f"→{item['tab']}タブ", item["what"]), tags=("warn",))
        self.tree.insert(node, "end", text=f"  なぜ: {item['why']}", values=("", ""), tags=("muted",))
        return node

    def _show_detail_text(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", text, "muted")
        self.detail.configure(state="disabled")

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        payload = self._nodes.get(sel[0]) if sel else None
        if payload is None and sel:                 # 子ノードを選んだら親の内容を出す
            payload = self._nodes.get(self.tree.parent(sel[0]))
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if payload:
            key, item = payload
            self._write_detail(key, item)
        self.detail.configure(state="disabled")

    def _write_detail(self, key, item):
        def put(text, tag="muted"):
            self.detail.insert("end", text, tag)

        if key == "advice":
            put(f"{item['title']}\n", "h")
            put(f"確信度: {item['confidence']}", CONF_TAG.get(item["confidence"], "muted"))
            put(f"    根拠データ: {item['source']}\n\n")
            put("根拠となった実測値\n", "h")
            for e in item["evidence"]:
                if e:
                    put(f"  ・{e}\n")
            if item["check_first"]:
                put("\n試す前に確認すること\n", "h")
                for c in item["check_first"]:
                    put(f"  ⚠ {c}\n", "warn")
            put("\n手順\n", "h")
            for n, s in enumerate(item["steps"], 1):
                put(f"  {n}) {s}\n", "good")
            put(f"\n期待できる効果: {item['expect']}\n")
        elif key == "no_effect":
            put(f"{item['title']}\n", "h")
            put("この対策は効果が見込めません。\n\n", "muted")
            put(f"{item['reason']}\n\n")
            for e in item["evidence"]:
                if e:
                    put(f"  ・{e}\n")
            put(f"\n根拠データ: {item['source']}\n")
        else:
            put(f"{item['title']}\n", "h")
            put(f"測るタブ: {item['tab']}\n", "warn")
            put(f"何を測る: {item['what']}\n\n")
            put(f"なぜ必要か: {item['why']}\n")

    # ---- 出力 ----

    def export(self):
        if not self.result:
            return
        try:
            nd.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            path = nd.RESULTS_DIR / f"advice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            path.write_text(to_markdown(self.result), encoding="utf-8")
        except OSError as e:
            self._set_status(f"出力に失敗しました: {e}", "bad")
            return
        self._set_status(f"✓ 出力: {path.name}", "good")

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


# ---------- 自己テスト (ネットワーク不要) ----------

def _good_full():
    return {
        "label": "good", "timestamp": "2026-08-24T12:00:00",
        "latency": {"gateway": {"avg_ms": 1, "loss_pct": 0},
                    "1.1.1.1": {"avg_ms": 7, "loss_pct": 0},
                    "8.8.8.8": {"avg_ms": 7, "loss_pct": 0}},
        "dns": {"router": {"avg_ms": 12.0}, "1.1.1.1": {"avg_ms": 11.0}, "8.8.8.8": {"avg_ms": 13.0}},
        "throughput": {"single": {"mbps": 850.0}, "parallel6": {"mbps": 930.0}},
        "upload": {"single": {"mbps": 800.0}, "parallel6": {"mbps": 880.0}},
        "bufferbloat": {"idle_latency": {"avg_ms": 7, "loss_pct": 0},
                        "loaded_latency": {"avg_ms": 8, "loss_pct": 0},
                        "increase_pct": 14.3, "rpm_approx": 7500},
        "link_stats": {"tcp_retransmit_pct": 0.12, "tcp_segments_sent": 1000000,
                       "tcp_segments_retransmitted": 1200,
                       "adapters": [{"Name": "イーサネット", "ReceivedDiscardedPackets": 0,
                                     "ReceivedPacketErrors": 0}],
                       "link": [{"Name": "イーサネット", "LinkSpeed": "1 Gbps"}]},
        "path_mtu": {"mtu": 1500, "max_payload": 1472, "interpretation": "標準的なイーサネット"},
        "jitter": {"jitter_ms": 1.2, "mos": 4.4, "avg_rtt_ms": 7.1},
        "nat": {"nat_type": "Cone NAT (ポート保存型)", "external_ports": [50000, 50000, 50000]},
        "ipv6": {"has_global_address": True, "has_default_route": True, "egress_reachable": True},
    }


def _src(data, name="x.json", days_ago=0):
    return {"path": Path(name), "name": name,
            "mtime": datetime.now() - timedelta(days=days_ago),
            "timestamp": data.get("timestamp") if isinstance(data, dict) else None, "data": data}


def _all_missing():
    return {k: None for k in KINDS}


def _titles(items):
    return " | ".join(i["title"] for i in items)


def _selftest():
    # --- ① 全部良好 -> 対処提案は出ない ---
    s = _all_missing()
    s["full"] = _src(_good_full(), "full_v2_20260824_120000.json")
    ev = evaluate(s, contract_mbps=1000)
    assert ev["advice"] == [], _titles(ev["advice"])
    assert ev["grade"]["grade"] in "ABCDEF", ev["grade"]
    # 良好なものは「効果なし」側に回る
    ne = _titles(ev["no_effect"])
    assert "MTU" in ne and "ping" in ne, ne
    assert to_markdown(ev).startswith("# ネットワーク総合診断"), "Markdownが生成できる"
    assert "対処が必要な問題は検出されませんでした" in to_markdown(ev)

    # --- ② 速度だけ悪い -> 速度の提案が最上位 ---
    slow = _good_full()
    slow["throughput"] = {"single": {"mbps": 120.0}, "parallel6": {"mbps": 130.0}}
    slow["upload"] = {"single": {"mbps": 110.0}, "parallel6": {"mbps": 125.0}}
    s2 = _all_missing()
    s2["full"] = _src(slow)
    ev2 = evaluate(s2, contract_mbps=1000)
    assert ev2["advice"], "速度不足で提案が出るはず"
    top = ev2["advice"][0]
    assert "契約の 13%" in top["title"], top["title"]
    assert top["confidence"] == CONF_CERTAIN, top["confidence"]
    # 根拠に実測値そのものが載っている
    assert any("130 Mbps" in e and "1000 Mbps" in e for e in top["evidence"]), top["evidence"]
    # 断定せず、無線帯域の可能性を確認事項として持っている(過去の誤診断の再発防止)
    assert any("2.4GHz" in c for c in top["check_first"]), top["check_first"]
    # 契約速度は設定から。契約が低ければ同じ実測でも提案は出ない
    assert evaluate(s2, contract_mbps=150)["advice"] == []

    # --- ③ データが欠けている -> 要追加測定に回り、提案にはならない ---
    ev3 = evaluate(_all_missing())
    assert ev3["advice"] == [], _titles(ev3["advice"])
    assert ev3["grade"] is None
    more_titles = _titles(ev3["more"])
    for word in ("フル診断", "DNS", "Windows", "サービス", "経路上", "時間帯", "スパイク", "ポート開放"):
        assert word in more_titles, (word, more_titles)
    assert all(m["tab"] and m["what"] and m["why"] for m in ev3["more"])

    # --- ④ {"error": ...} を含むデータでも落ちない ---
    broken = {"label": "broken", "timestamp": "2026-08-24T00:00:00",
              "throughput": {"error": "接続できません"}, "upload": {"error": "timeout"},
              "latency": {"error": "x"}, "bufferbloat": {"error": "x"},
              "link_stats": {"error": "x"}, "path_mtu": {"error": "x"},
              "jitter": {"error": "x"}, "nat": {"error": "x"}, "ipv6": {"error": "x"},
              "dns": {"error": "x"}}
    s4 = _all_missing()
    s4["full"] = _src(broken)
    s4["tuning"] = _src({"summary": "x", "findings": "これはリストではない"})
    s4["services"] = _src({"services": None, "outliers": "not-a-list"})
    s4["pathmon"] = _src({"hops": [None, "x", {"hop": 1}]})
    s4["dnsaudit"] = _src({"dnssec": {"rows": "x"}, "nxdomain": None})
    s4["trend"] = {"path": Path("trend.jsonl"), "name": "trend.jsonl",
                   "mtime": datetime.now(), "timestamp": None,
                   "data": [{"ts": "bad"}, {"down_mbps": True}, "not-a-dict"]}
    s4["watchdog"] = {"path": Path("w.jsonl"), "name": "w.jsonl", "mtime": datetime.now(),
                      "timestamp": None, "data": [{"type": "切断", "detail": "x"}, "junk"]}
    ev4 = evaluate(s4, contract_mbps=1000)
    assert isinstance(ev4["advice"], list)
    assert to_markdown(ev4)
    # 数値が取れないセクションは提案を作らない(「-」を根拠に断定しない)
    assert not any("契約の" in a["title"] for a in ev4["advice"]), _titles(ev4["advice"])
    # watchdog の切断は拾える
    assert any("切断 1 件" in a["title"] for a in ev4["advice"]), _titles(ev4["advice"])

    # --- ⑤ 確信度の割り当て ---
    # 5-a. STUN の外部ポートが「連番に近い」= 測定側の副作用 -> 提案にせず要追加測定へ
    sym = _good_full()
    sym["nat"] = {"nat_type": "Symmetric NAT (宛先ごとにポートが変わる)",
                  "external_ports": [64194, 64195, 64196]}
    s5 = _all_missing()
    s5["full"] = _src(sym)
    ev5 = evaluate(s5, contract_mbps=1000)
    assert not any("Symmetric" in a["title"] for a in ev5["advice"]), \
        "連番ポートを根拠に Symmetric と断定してはいけない"
    nat_more = [m for m in ev5["more"] if "NAT" in m["title"]]
    assert nat_more and "送信元ポート" in nat_more[0]["why"], nat_more

    # 5-b. 外部ポートがばらばらなら提案にはするが、確信度は「弱い」まで
    sym2 = _good_full()
    sym2["nat"] = {"nat_type": "Symmetric NAT (宛先ごとにポートが変わる)",
                   "external_ports": [1024, 33000, 61000]}
    s5b = _all_missing()
    s5b["full"] = _src(sym2)
    nat_adv = [a for a in evaluate(s5b, contract_mbps=1000)["advice"] if "Symmetric" in a["title"]]
    assert nat_adv and nat_adv[0]["confidence"] == CONF_WEAK, nat_adv
    assert any("送信元ポート" in c for c in nat_adv[0]["check_first"])

    # 5-c. 負荷時損失: アイドルが綺麗なら「強い」、アイドルも汚れていれば「弱い」
    loss = _good_full()
    loss["bufferbloat"] = {"idle_latency": {"avg_ms": 8, "loss_pct": 0},
                           "loaded_latency": {"avg_ms": 14, "loss_pct": 20},
                           "increase_pct": 75.0, "rpm_approx": 4286}
    s6 = _all_missing()
    s6["full"] = _src(loss)
    ev6 = evaluate(s6, contract_mbps=1000)
    la = [a for a in ev6["advice"] if "落ちている" in a["title"] and "混雑時" in a["title"]]
    assert la and la[0]["confidence"] == CONF_STRONG, la
    assert any("20%" in e for e in la[0]["evidence"]), la[0]["evidence"]
    assert any("ICMP" in c for c in la[0]["check_first"]), "競合する説明を明示すること"
    loss2 = json.loads(json.dumps(loss))
    loss2["bufferbloat"]["idle_latency"]["loss_pct"] = 8
    s6b = _all_missing()
    s6b["full"] = _src(loss2)
    la2 = [a for a in evaluate(s6b, contract_mbps=1000)["advice"] if "混雑時" in a["title"]]
    assert la2 and la2[0]["confidence"] == CONF_WEAK, la2

    # 5-d. TCP再送率: 3%以上は「強い」だが、累計値である旨を必ず確認事項に持つ
    rex = _good_full()
    rex["link_stats"] = dict(rex["link_stats"], tcp_retransmit_pct=3.604,
                             tcp_segments_sent=8676373, tcp_segments_retransmitted=312712)
    s7 = _all_missing()
    s7["full"] = _src(rex)
    ra = [a for a in evaluate(s7, contract_mbps=1000)["advice"] if "TCP再送率" in a["title"]]
    assert ra and ra[0]["confidence"] == CONF_STRONG, ra
    assert any("312,712" in e and "8,676,373" in e for e in ra[0]["evidence"]), ra[0]["evidence"]
    assert any("起動からの累計" in c for c in ra[0]["check_first"]), ra[0]["check_first"]
    # 1%未満なら「効果なし」側
    assert any("再送率は 0.120%" in n["reason"] for n in evaluate(s, contract_mbps=1000)["no_effect"])

    # 5-e. 設定値そのものを読む Windows設定 と DNSハイジャックは「確定」
    s8 = _all_missing()
    s8["full"] = _src(_good_full())
    s8["tuning"] = _src({"summary": "要対処 1 件", "findings": [
        {"sev": 0, "cat": "TCP", "item": "受信ウィンドウ自動チューニングが無効",
         "current": "disabled", "recommend": "normal", "why": "高速回線で頭打ちになる",
         "cmd": "netsh int tcp set global autotuninglevel=normal"},
        {"sev": 2, "cat": "TCP", "item": "RSS", "current": "enabled", "recommend": "enabled",
         "why": "", "cmd": ""}]}, "tuning_20260824_120000.json")
    s8["dnsaudit"] = _src({"timestamp": "2026-08-24T12:00:00", "nxdomain": {"rows": [
        {"label": "存在しないドメイン", "measured": "A=203.0.113.9", "verdict": "乗っ取り", "tag": "bad"}]},
        "dnssec": {"rows": [
            {"label": "ルーター (192.168.3.1)", "measured": "AD=0", "verdict": "検証なし", "tag": "warn"},
            {"label": "1.1.1.1", "measured": "AD=1", "verdict": "検証あり", "tag": "good"}]}},
        "dnsaudit_20260824_120000.json")
    ev8 = evaluate(s8, contract_mbps=1000)
    hij = [a for a in ev8["advice"] if "ハイジャック" in a["title"]]
    assert hij and hij[0]["confidence"] == CONF_CERTAIN, hij
    win = [a for a in ev8["advice"] if a["title"].startswith("Windows設定")]
    assert len(win) == 1 and win[0]["confidence"] == CONF_CERTAIN, win
    assert any("netsh int tcp set global" in s_ for s_ in win[0]["steps"]), win[0]["steps"]
    dnssec = [a for a in ev8["advice"] if "DNSSEC" in a["title"]]
    assert dnssec and dnssec[0]["confidence"] == CONF_CERTAIN, dnssec
    assert any("1.1.1.1" in s_ for s_ in dnssec[0]["steps"]), dnssec[0]["steps"]
    # 優先度: ハイジャック(85) > Windows設定(48) > DNSSEC(32)
    order = [a["title"] for a in ev8["advice"]]
    assert order.index(hij[0]["title"]) < order.index(win[0]["title"]) < order.index(dnssec[0]["title"]), order

    # 5-f. 中間ホップだけの損失は ICMP レート制限として「効果なし」に落とす
    s9 = _all_missing()
    s9["full"] = _src(_good_full())
    s9["pathmon"] = _src({"target": "1.1.1.1", "cycles": 50, "hops": [
        {"hop": 1, "ip": "192.168.3.1", "loss_pct": 0.0, "sent": 50, "recv": 50},
        {"hop": 2, "ip": "10.0.0.1", "loss_pct": 40.0, "sent": 50, "recv": 30},
        {"hop": 3, "ip": "1.1.1.1", "loss_pct": 0.0, "sent": 50, "recv": 50}]},
        "pathmon_20260824_120000.json")
    ev9 = evaluate(s9, contract_mbps=1000)
    assert not any("経路上で継続的に" in a["title"] for a in ev9["advice"]), _titles(ev9["advice"])
    assert any("ICMP" in n["reason"] for n in ev9["no_effect"])
    # 最終ホップまで落ちていれば本物として提案する
    s9b = _all_missing()
    s9b["full"] = _src(_good_full())
    s9b["pathmon"] = _src({"cycles": 50, "hops": [
        {"hop": 1, "ip": "192.168.3.1", "loss_pct": 0.0, "sent": 50, "recv": 50},
        {"hop": 2, "ip": "10.0.0.1", "loss_pct": 40.0, "sent": 50, "recv": 30},
        {"hop": 3, "ip": "1.1.1.1", "loss_pct": 38.0, "sent": 50, "recv": 31}]})
    pa = [a for a in evaluate(s9b, contract_mbps=1000)["advice"] if "経路上で継続的に" in a["title"]]
    assert pa and pa[0]["confidence"] == CONF_STRONG, pa

    # 5-g. トレンドは件数が足りなければ提案せず「データ不足」と明示する
    s10 = _all_missing()
    s10["full"] = _src(_good_full())
    s10["trend"] = {"path": Path("trend.jsonl"), "name": "trend.jsonl", "mtime": datetime.now(),
                    "timestamp": None,
                    "data": [{"ts": "2026-08-24T01:00:00", "hour": 1, "down_mbps": 900}]}
    ev10 = evaluate(s10, contract_mbps=1000)
    lack = [m for m in ev10["more"] if "時間帯" in m["title"]]
    assert lack and "データ不足" in lack[0]["title"], lack
    assert "1 件" in lack[0]["why"], lack[0]["why"]
    # 十分たまっていて差が大きければ提案する
    recs = []
    for hour, mbps in ((2, 900), (12, 880), (21, 300)):
        recs += [{"ts": f"2026-08-2{i}T{hour:02d}:00:00", "hour": hour, "down_mbps": mbps + i}
                 for i in range(4)]
    s10b = _all_missing()
    s10b["full"] = _src(_good_full())
    s10b["trend"] = {"path": Path("trend.jsonl"), "name": "trend.jsonl",
                     "mtime": datetime.now(), "timestamp": None, "data": recs}
    ta = [a for a in evaluate(s10b, contract_mbps=1000)["advice"] if "時間帯" in a["title"]]
    assert ta and ta[0]["confidence"] == CONF_STRONG, ta
    assert "21時台" in ta[0]["title"], ta[0]["title"]

    # --- 古いデータには注意書きが付く ---
    s11 = _all_missing()
    s11["full"] = _src(_good_full(), "old.json", days_ago=30)
    assert any("30 日前" in n for n in evaluate(s11, contract_mbps=1000)["notes"])

    # --- 全提案が必須フィールドを持つ ---
    for source_set in (s2, s5b, s6, s7, s8, s9b, s10b):
        for a in evaluate(source_set, contract_mbps=1000)["advice"]:
            assert a["confidence"] in CONF_TAG, a
            assert a["title"] and a["steps"] and a["expect"] and a["source"], a
            assert [e for e in a["evidence"] if e], a
            assert isinstance(a["priority"], int), a

    # --- collect(): 空ディレクトリでも落ちない / JSONLと壊れたJSONを扱える ---
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        assert all(v is None for v in collect(d).values())
        (d / "full_v2_20260824_010101.json").write_text(
            json.dumps(_good_full(), ensure_ascii=False), encoding="utf-8")
        (d / "dnsaudit_20260824_010101.json").write_text("{ 壊れている", encoding="utf-8")
        (d / "trend.jsonl").write_text('{"ts":"2026-08-24T01:00:00","down_mbps":900}\n'
                                       'これは JSON ではない\n', encoding="utf-8")
        (d / "watchdog_20260824.jsonl").write_text("", encoding="utf-8")
        got = collect(d)
        assert got["full"] and got["full"]["data"]["label"] == "good"
        assert got["dnsaudit"] is None, "壊れたJSONは無かったことにする"
        assert got["trend"] and len(got["trend"]["data"]) == 1
        assert got["watchdog"] is None, "空のJSONLは無かったことにする"
        assert evaluate(got, contract_mbps=1000)["advice"] == []

    print("advisor selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import tkinter as tk
    from tkinter import ttk

    import sv_ttk

    root = tk.Tk()
    root.title("総合診断・対処提案")
    root.geometry("1200x760")
    sv_ttk.set_theme("dark")

    class Ctx:
        pass

    ctx = Ctx()
    ctx.root = root
    ctx.font = "Segoe UI"
    ctx.theme = {"bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
                 "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
                 "graph_bg": "#232323", "graph_grid": "#3a3a3a"}
    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)
    tab = AdvisorTab(frame, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
