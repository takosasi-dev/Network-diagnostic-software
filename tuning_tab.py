#!/usr/bin/env python3
"""Windows ネットワーク設定監査タブ。「回線が遅い」の原因が回線側ではなく
Windows 側の設定にあるケースを洗い出す。

**このモジュールは読み取り専用。設定を変更する処理は一切持たない。**
検出した項目には「現在値 / 推奨値 / なぜそう推奨するか / 変更コマンド(表示のみ)」を添え、
実行するかどうかの判断はユーザーに委ねる。

実機で確認した採取方法の注意点(推測で書くと壊れる箇所):

1. netsh の出力は UTF-8。cp932 で読むと UnicodeDecodeError で落ちる。
   実測: `netsh int tcp show global` の先頭バイトは b'\\xe3\\x82\\xa2' (= 'ア')。
   よって nd.run(..., encoding="utf-8") 必須。
2. さらに netsh はサブプロセス起動だと**日本語**を吐く(対話コンソールでは英語に見えることがある)。
   つまり日本語ラベルのパースが本番経路。両方の表記に対応させてある。
3. netsh の日本語ラベルには包含関係がある。実測で
   「Fast Open」と「Fast Open フォールバック」が共存しており、部分一致で拾うと取り違える。
   よって空白正規化したうえで**ラベル全体の集合一致**で突き合わせる。
4. PowerShell 側は ConvertTo-Json で構造化して取る。ただし PS 5.1 の ConvertTo-Json は
   (a) 列挙型を数値に落とす → [string] にキャストしてから渡す
   (b) 要素1個の配列をオブジェクトに潰す → Python 側 _as_list() で吸収
"""
import json
import re
import threading
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import ttk

import network_diag as nd

# 重大度。小さいほど優先。
SEV_ACTION, SEV_ADVISE, SEV_INFO = 0, 1, 2
SEV_LABEL = {SEV_ACTION: "要対処", SEV_ADVISE: "推奨", SEV_INFO: "情報"}
SEV_TAG = {SEV_ACTION: "bad", SEV_ADVISE: "warn", SEV_INFO: "muted"}

# 受信破棄・再送率のしきい値。再送は 1% 未満が正常、2% を超えると体感に出る水準。
DISCARD_WARN_PCT = 0.1
RETRANS_ADVISE_PCT = 1.0
RETRANS_ACTION_PCT = 2.0


# ---------- netsh int tcp show global のパース ----------

# ラベル全体の集合。空白は正規化済みの形で持つ(実機の日本語出力から採取)。
_NETSH_LABELS = {
    "rss": {"Receive-Side Scaling 状態", "Receive-Side Scaling State"},
    "autotuning": {"受信ウィンドウ自動チューニング レベル", "Receive Window Auto-Tuning Level"},
    "congestion": {"アドオン輻輳制御プロバイダー", "Add-On Congestion Control Provider"},
    "ecn": {"ECN 機能", "ECN Capability"},
    "timestamps": {"RFC 1323 タイムスタンプ", "RFC 1323 Timestamps"},
    "initial_rto": {"初期 RTO", "Initial RTO"},
    "rsc": {"Receive Segment Coalescing 状態", "Receive Segment Coalescing State"},
    "non_sack": {"非 Sack の Rtt 回復性", "Non Sack Rtt Resiliency"},
    "max_syn": {"SYN の最大再送信数", "Max SYN Retransmissions"},
    "fast_open": {"Fast Open"},
    "fast_open_fallback": {"Fast Open フォールバック", "Fast Open Fallback"},
    "hystart": {"HyStart"},
    "prr": {"Proportional Rate Reduction"},
    "pacing": {"ペーシング プロファイル", "Pacing Profile"},
}

# 表示用の日本語見出し
NETSH_TITLE = {
    "rss": "RSS (受信側スケーリング)", "autotuning": "受信ウィンドウ自動チューニング",
    "congestion": "アドオン輻輳制御プロバイダー", "ecn": "ECN 機能",
    "timestamps": "RFC 1323 タイムスタンプ", "initial_rto": "初期 RTO (ms)",
    "rsc": "RSC (受信セグメント合体)", "non_sack": "非 SACK RTT 回復性",
    "max_syn": "SYN 最大再送信数", "fast_open": "TCP Fast Open",
    "fast_open_fallback": "TCP Fast Open フォールバック", "hystart": "HyStart",
    "prr": "Proportional Rate Reduction", "pacing": "ペーシング プロファイル",
}


def _norm_label(s):
    return re.sub(r"\s+", " ", s).strip()


def parse_netsh_tcp_global(text):
    """`netsh int tcp show global` -> {canonical_key: value}

    ラベルは空白正規化のうえ完全一致で判定する。部分一致にすると
    「Fast Open」が「Fast Open フォールバック」を巻き込む(実機で共存を確認済み)。
    """
    out = {}
    for line in text.splitlines():
        label, sep, value = line.partition(":")
        if not sep:
            continue
        label, value = _norm_label(label), value.strip()
        if not label or not value:
            continue
        for key, names in _NETSH_LABELS.items():
            if label in names:
                out[key] = value
                break
    return out


# ---------- netsh interface ipvX show subinterfaces のパース ----------

def parse_subinterfaces(text):
    """-> [{"name": str, "mtu": int}]  ループバックは除く。

    固定幅の表。先頭列が MTU、最終列がインタフェース名(空白を含みうる)なので
    maxsplit=4 で分割し、先頭が数字の行だけをデータ行とみなす。
    """
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 4)
        if len(parts) != 5 or not parts[0].isdigit():
            continue
        name = parts[4].strip()
        if name.lower().startswith("loopback"):
            continue
        rows.append({"name": name, "mtu": int(parts[0])})
    return rows


# ---------- PMTUD (経路MTU探索) が生きているかの判定 ----------

def classify_pmtud(ping_text):
    """経路MTU超過サイズの DF 付き ping の出力 -> 判定文字列。

    "ok"        : ICMP Fragmentation Needed が返っている(または stack がキャッシュ済み) = PMTUD 正常
    "passed"    : 素通りした(このサイズで通るなら経路MTUの見積りが古い)
    "blackhole" : 応答なし = ICMP が途中で捨てられている疑い
    "unknown"   : 判定不能
    """
    low = ping_text.lower()
    # 断片化要求の判定を先に置く。日本語の成功応答には「時間 =」が付くが、
    # 断片化応答には付かないので取り違えない。
    if "断片化" in ping_text or "needs to be fragmented" in low or "df set" in low:
        return "ok"
    if "ttl=" in low or "time=" in low or "時間 =" in ping_text or "時間=" in ping_text:
        return "passed"
    if "タイムアウト" in ping_text or "timed out" in low or "要求がタイムアウト" in ping_text:
        return "blackhole"
    return "unknown"


# ---------- 値の正規化 ----------

def is_enabled(value):
    """NICの詳細プロパティ値 -> True/False/None。

    「受信と伝送有効」「Rx & Tx Enabled」のような複合値があるため部分一致だが、
    「無効」に「有効」は含まれないので**無効側を先に判定**すれば取り違えない。
    """
    if value is None:
        return None
    s = str(value).strip()
    low = s.lower()
    if "無効" in s or "disabled" in low or low in ("off", "0", "false"):
        return False
    if "有効" in s or "enabled" in low or low in ("on", "1", "true"):
        return True
    return None


def _as_list(v):
    """PS 5.1 の ConvertTo-Json は要素1個の配列をオブジェクトに潰すので吸収する。"""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _num(s):
    # str(s or "") にすると整数の 0 が "" に潰れ、「0という設定値」と「値なし」が
    # 区別できなくなる。SearchOrderConfig=0 のように 0 が意味を持つ項目があるので
    # None だけを空扱いにする。
    m = re.search(r"-?\d+", "" if s is None else str(s))
    return int(m.group()) if m else None


# ---------- PowerShell 一括採取 ----------

# powershell.exe の起動は1回あたり 0.4s 前後かかるので、全項目を1回のJSONで取る。
# 列挙型は [string] にキャストしないと数値で落ちてくる(実測: CongestionProvider -> 5)。
PS_COLLECT = r"""
$ErrorActionPreference='SilentlyContinue'
function T($b){ try { & $b } catch { $null } }
function S($v){ if ($null -eq $v) { $null } else { [string]$v } }
$o=[ordered]@{}
$o.tcp = T { Get-NetTCPSetting | Select-Object SettingName,
    @{n='AutoTuningLevelLocal';e={S $_.AutoTuningLevelLocal}},
    @{n='AutoTuningLevelEffective';e={S $_.AutoTuningLevelEffective}},
    @{n='CongestionProvider';e={S $_.CongestionProvider}},
    @{n='EcnCapability';e={S $_.EcnCapability}},
    @{n='Timestamps';e={S $_.Timestamps}},
    @{n='ScalingHeuristics';e={S $_.ScalingHeuristics}},
    @{n='NonSackRttResiliency';e={S $_.NonSackRttResiliency}},
    InitialRto,MinRto,InitialCongestionWindow,MaxSynRetransmissions,DelayedAckTimeout }
$o.offload = T { Get-NetOffloadGlobalSetting | Select-Object
    @{n='ReceiveSideScaling';e={S $_.ReceiveSideScaling}},
    @{n='ReceiveSegmentCoalescing';e={S $_.ReceiveSegmentCoalescing}},
    @{n='Chimney';e={S $_.Chimney}},
    @{n='TaskOffload';e={S $_.TaskOffload}},
    @{n='NetworkDirect';e={S $_.NetworkDirect}},
    @{n='PacketCoalescingFilter';e={S $_.PacketCoalescingFilter}} }
$o.adapters = T { Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,
    @{n='Status';e={S $_.Status}},LinkSpeed,FullDuplex,MtuSize,DriverVersion,DriverDate,ifIndex }
$o.advanced = T { Get-NetAdapterAdvancedProperty -Name * | Select-Object Name,DisplayName,
    DisplayValue,RegistryKeyword,NumericParameterMaxValue,NumericParameterMinValue }
$o.power = @(); $o.power_error = $null
try { $o.power = @(Get-NetAdapterPowerManagement -Name * -ErrorAction Stop | Select-Object Name,
    @{n='AllowComputerToTurnOffDevice';e={S $_.AllowComputerToTurnOffDevice}},
    @{n='DeviceSleepOnDisconnect';e={S $_.DeviceSleepOnDisconnect}},
    @{n='WakeOnMagicPacket';e={S $_.WakeOnMagicPacket}},
    @{n='WakeOnPattern';e={S $_.WakeOnPattern}}) }
catch { $o.power_error = $_.Exception.Message }
$o.pnpcap = T { Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' |
    ForEach-Object { $p=Get-ItemProperty $_.PSPath
        if($p.DriverDesc){ [pscustomobject]@{Desc=$p.DriverDesc; PnPCapabilities=$p.PnPCapabilities} } } }
$o.dns_servers = T { Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } |
    Select-Object InterfaceAlias,AddressFamily,@{n='Servers';e={$_.ServerAddresses -join ', '}} }
$o.dns_cache_count = T { (Get-DnsClientCache | Measure-Object).Count }
$o.netbios = T { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
    Select-Object Description,TcpipNetbiosOptions }
$o.llmnr = T { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient').EnableMulticast }
$o.mdns  = T { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters').EnableMDNS }
$o.qos = T { Get-NetQosPolicy | Select-Object Name,IPProtocol,IPDstPortStart,
    ThrottleRateActionBitsPerSecond,PriorityValue8021Action }
$o.profiles = T { Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,
    @{n='NetworkCategory';e={S $_.NetworkCategory}},
    @{n='IPv4Connectivity';e={S $_.IPv4Connectivity}},
    @{n='IPv6Connectivity';e={S $_.IPv6Connectivity}} }
$o.delivery = T { Get-DOConfig | Select-Object DownloadMode,MaxUploadRatePct,UploadLimitMonthlyGB,DownBackLimitPct }
$o.stats = T { Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Get-NetAdapterStatistics |
    Select-Object Name,ReceivedUnicastPackets,ReceivedDiscardedPackets,ReceivedPacketErrors,
    OutboundDiscardedPackets,OutboundPacketErrors }
$o | ConvertTo-Json -Depth 4 -Compress
"""

# Delivery Optimization の DownloadMode。1/2/3 は他PCとの P2P 配信を行う。
DO_MODES = {0: "CdnOnly (P2Pなし)", 1: "LAN内のPCとP2P", 2: "同一グループ内でP2P",
            3: "インターネット越しにP2P", 99: "Simple (P2Pなし)", 100: "Bypass"}
DO_P2P = (1, 2, 3)

# NIC 詳細プロパティの省電力系。レジストリキーワードはロケール非依存なのでこれをキーにする。
POWER_SAVE_KEYWORDS = {
    "*EEE": "省電力型イーサネット (EEE)",
    "AdvancedEEE": "Advanced EEE",
    "EnableGreenEthernet": "グリーンイーサネット",
    "PowerSavingMode": "Power Saving Mode",
    "GigaLite": "Gigabit Lite",
    "*SelectiveSuspend": "セレクティブサスペンド",
}

OFFLOAD_KEYWORDS = {
    "*LsoV2IPv4": "一括送信オフロード v2 (IPv4)",
    "*LsoV2IPv6": "一括送信オフロード v2 (IPv6)",
    "*TCPChecksumOffloadIPv4": "TCP チェックサムオフロード (IPv4)",
    "*TCPChecksumOffloadIPv6": "TCP チェックサムオフロード (IPv6)",
    "*IPChecksumOffloadIPv4": "IPv4 チェックサムオフロード",
    "*UDPChecksumOffloadIPv4": "UDP チェックサムオフロード (IPv4)",
    "*UDPChecksumOffloadIPv6": "UDP チェックサムオフロード (IPv6)",
}


# Windows Update にドライバ更新が来ているかを問い合わせる。
# 「0件」を「最新です」と言い切らないために、抑止設定と検索機構の生死も一緒に採る。
#   - WUServer が入っていれば WSUS 管理下 → 一般のドライバ更新は降ってこない
#   - SearchOrderConfig=0 は「Windows Update でドライバを検索しない」
#   - ExcludeWUDriversInQualityUpdate=1 は品質更新からドライバを除外
# other_count は非ドライバの未適用更新数。1件以上返れば検索機構が生きている証拠になる。
PS_DRIVER_UPDATES = r"""
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$pol='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$drv='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'
$o.wsus = (Get-ItemProperty $pol).WUServer
$o.exclude_wu_drivers = (Get-ItemProperty $pol).ExcludeWUDriversInQualityUpdate
$o.search_order = (Get-ItemProperty $drv).SearchOrderConfig
$o.error = $null
$o.drivers = @()
$o.other_count = $null
try {
  $se = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $se.ServerSelection = 2
  $r = $se.Search("IsInstalled=0")
  $d = @($r.Updates | Where-Object { $_.Type -eq 2 })
  $o.other_count = @($r.Updates).Count - $d.Count
  $o.drivers = @($d | ForEach-Object {
      [pscustomobject]@{ Title=[string]$_.Title; DriverClass=[string]$_.DriverClass
                         DriverModel=[string]$_.DriverModel; Date=[string]$_.DriverVerDate } })
} catch { $o.error = $_.Exception.Message }
$o | ConvertTo-Json -Depth 4 -Compress
"""


def driver_update_state(wu):
    """WU問い合わせ結果 -> (状態キー, 表示文字列)。
    「確認できていない」と「確認したうえで0件」を絶対に混ぜない。前者を後者として
    報告すると、古いドライバのまま「最新です」と言うことになる。"""
    if not wu or wu.get("error"):
        return "unknown", (wu or {}).get("error") or "問い合わせしていない"
    if wu.get("wsus"):
        return "suppressed", f"WSUS管理下 ({wu['wsus']})"
    if _num(wu.get("search_order")) == 0:
        return "suppressed", "SearchOrderConfig=0 (WUでドライバを検索しない設定)"
    if _num(wu.get("exclude_wu_drivers")) == 1:
        return "suppressed", "ExcludeWUDriversInQualityUpdate=1 (品質更新からドライバを除外)"
    drivers = _as_list(wu.get("drivers"))
    if drivers:
        return "available", f"{len(drivers)}件"
    if not _num(wu.get("other_count")):
        # 0件だが、未適用の更新が他にも無いので検索機構が生きている裏付けが取れていない
        return "none_unproven", "0件 (検索機構の生死は未確認)"
    return "none", "0件"


def collect(progress=lambda _m: None, mtu_host="1.1.1.1"):
    """監査に必要な生データを集める。ネットワークI/Oを伴うのでワーカースレッドから呼ぶこと。"""
    data = {"timestamp": datetime.now().isoformat(timespec="seconds"), "errors": []}

    progress("PowerShell から設定を採取中...")
    try:
        raw = nd.ps(PS_COLLECT, timeout=120)
        data["ps"] = json.loads(raw) if raw.strip() else {}
    except Exception as e:
        data["ps"] = {}
        data["errors"].append(f"PowerShell 採取に失敗: {e}")

    progress("netsh から TCP グローバルパラメータを採取中...")
    # netsh は UTF-8。cp932 を指定すると UnicodeDecodeError で落ちる(実機で確認済み)。
    try:
        data["netsh_raw"] = nd.run(["netsh", "int", "tcp", "show", "global"],
                                   timeout=20, encoding="utf-8").stdout
        data["netsh_tcp"] = parse_netsh_tcp_global(data["netsh_raw"])
    except Exception as e:
        data["netsh_tcp"] = {}
        data["errors"].append(f"netsh int tcp show global に失敗: {e}")

    for key, fam in (("subif4", "ipv4"), ("subif6", "ipv6")):
        try:
            out = nd.run(["netsh", "interface", fam, "show", "subinterfaces"],
                         timeout=20, encoding="utf-8").stdout
            data[key] = parse_subinterfaces(out)
        except Exception as e:
            data[key] = []
            data["errors"].append(f"netsh interface {fam} show subinterfaces に失敗: {e}")

    progress("経路MTUを探索中 (DF付きpingの二分探索)...")
    data["path_mtu"] = nd.discover_path_mtu(mtu_host)

    payload = data["path_mtu"].get("max_payload")
    if payload:
        progress("PMTUD (ICMP Fragmentation Needed) が届くか確認中...")
        # 経路MTUを1バイト超えるサイズを DF 付きで投げる。
        # ICMP が返れば PMTUD 正常、無反応ならブラックホールの疑い。
        try:
            out = nd.run(["ping", "-f", "-l", str(payload + 1), "-n", "1", "-w", "2000", mtu_host],
                         timeout=15).stdout
            data["pmtud_raw"] = out
            data["pmtud"] = classify_pmtud(out)
        except Exception as e:
            data["pmtud"] = "unknown"
            data["errors"].append(f"PMTUD 確認に失敗: {e}")
    else:
        data["pmtud"] = "unknown"

    progress("Windows Update にドライバ更新を問い合わせ中 (30秒ほどかかる)...")
    try:
        raw = nd.ps(PS_DRIVER_UPDATES, timeout=180)
        data["wu"] = json.loads(raw) if raw.strip() else {}
    except Exception as e:
        data["wu"] = {"error": str(e)}
        data["errors"].append(f"Windows Update への問い合わせに失敗: {e}")

    progress("TCP再送率・NICカウンタを採取中...")
    try:
        data["link"] = nd.get_link_stats()
    except Exception as e:
        data["link"] = {}
        data["errors"].append(f"get_link_stats に失敗: {e}")

    return data


# ---------- 判定 ----------

def _driver_age_days(raw):
    """DriverDate -> 今日までの日数。PS の ConvertTo-Json は日付を "/Date(...)/" 形式か
    ISO 文字列のどちらかで出すので両方受ける。読めなければ None
    (推測で「古い」と言わないため)。"""
    if not raw:
        return None
    text = str(raw)
    m = re.search(r"/Date\((-?\d+)", text)
    try:
        if m:
            dt = datetime.fromtimestamp(int(m.group(1)) / 1000)
        else:
            dt = datetime.fromisoformat(text.replace("Z", "").split("+")[0].strip())
    except Exception:
        return None
    return max(0, (datetime.now() - dt).days)


def _f(sev, cat, item, current, recommend, why, cmd=""):
    return {"sev": sev, "cat": cat, "item": item, "current": str(current),
            "recommend": recommend, "why": why, "cmd": cmd}


def _adv_index(ps, adapter_names):
    """RegistryKeyword -> row。物理アダプタの分だけに絞る。"""
    idx = {}
    for row in _as_list(ps.get("advanced")):
        if adapter_names and row.get("Name") not in adapter_names:
            continue
        kw = row.get("RegistryKeyword")
        if kw:
            idx.setdefault(kw, row)
    return idx


def analyze(data):
    """収集データ -> 重大度順の所見リスト。根拠のある項目だけを挙げる。"""
    ps = data.get("ps") or {}
    out = []
    adapters = _as_list(ps.get("adapters"))
    up = [a for a in adapters if str(a.get("Status", "")).lower() == "up"] or adapters
    names = {a.get("Name") for a in adapters}
    adv = _adv_index(ps, names)

    # --- 1. MTU 整合 / PMTUD ---
    path = data.get("path_mtu") or {}
    path_mtu = path.get("mtu")
    subif = {r["name"]: r["mtu"] for r in data.get("subif4") or []}
    iface_mtu = next((subif[a["Name"]] for a in up if a.get("Name") in subif), None)
    if iface_mtu is None and subif:
        iface_mtu = sorted(subif.values())[0]
    pmtud = data.get("pmtud", "unknown")

    if path_mtu and iface_mtu:
        cur = f"インタフェースMTU {iface_mtu} / 実測経路MTU {path_mtu}"
        interp = path.get("interpretation", "")
        if iface_mtu <= path_mtu:
            out.append(_f(SEV_INFO, "MTU", "MTU整合", cur, "そのままで良い",
                          f"インタフェースMTUが経路MTU以下なので断片化もPMTUD依存も発生しない。({interp})"))
        elif pmtud == "ok":
            out.append(_f(
                SEV_INFO, "MTU", "MTU不一致 (PMTUD正常)", cur, "変更不要",
                "インタフェースMTUのほうが大きいが、経路MTU超過サイズをDF付きで送ったところ\n"
                "ICMP Fragmentation Needed が正しく返ってきた。Path MTU Discovery が\n"
                "機能しているため、Windowsは接続ごとに自動でセグメントサイズを 1460 相当に\n"
                f"下げる。MTUを手動で下げる必要はない。({interp})\n\n"
                "※ MTUを1460に固定すると、経路MTUがより大きい別の宛先に対しても\n"
                "　 不必要に小さいセグメントで通信することになり、むしろ効率が落ちる。",
                f"(参考・実行不要) netsh interface ipv4 set subinterface \"{next(iter(subif), '')}\" "
                f"mtu={path_mtu} store=persistent"))
        elif pmtud == "blackhole":
            out.append(_f(
                SEV_ACTION, "MTU", "PMTUDブラックホールの疑い", cur, f"MTU を {path_mtu} に下げる",
                "インタフェースMTUが経路MTUより大きいのに、超過サイズのDF付きパケットに対して\n"
                "ICMP Fragmentation Needed が返ってこない。経路上のどこかでICMPが破棄されており、\n"
                "Path MTU Discovery が機能していない可能性が高い。この状態では\n"
                "「小さいリクエストは通るのに、特定サイトのページだけ開かない/途中で止まる」\n"
                "という症状が出る(大きなパケットだけが黙って消える)。",
                f"netsh interface ipv4 set subinterface \"{next(iter(subif), '')}\" "
                f"mtu={path_mtu} store=persistent"))
        else:
            out.append(_f(SEV_ADVISE, "MTU", "MTU不一致 (PMTUD未確認)", cur, "PMTUD の動作を確認",
                          "インタフェースMTUが経路MTUより大きい。PMTUDが効いていれば問題ないが、\n"
                          "今回は確認プローブの結果を判定できなかった。",
                          f"ping -f -l {(path.get('max_payload') or 1432) + 1} 1.1.1.1"))
    elif path.get("error"):
        out.append(_f(SEV_INFO, "MTU", "経路MTU測定不可", path["error"], "-",
                      "ICMPがブロックされている等の理由で経路MTUを測れなかった。"))

    for r in data.get("subif6") or []:
        out.append(_f(SEV_INFO, "MTU", f"IPv6 MTU ({r['name']})", r["mtu"], "1500",
                      "IPv6ネイティブ区間のMTU。IPv4 over IPv6 の内側MTUとは別物。"))

    # --- 2. 速度とデュプレックス ---
    sd = adv.get("*SpeedDuplex")
    if sd:
        val = str(sd.get("DisplayValue", ""))
        auto = ("自動" in val) or ("auto" in val.lower())
        link = next((a.get("LinkSpeed") for a in up), "?")
        if auto:
            out.append(_f(SEV_INFO, "NIC", "速度とデュプレックス", f"{val} (実リンク {link})",
                          "自動ネゴシエーション", "オートネゴシエーションが有効。推奨どおり。"))
        else:
            out.append(_f(
                SEV_ACTION, "NIC", "速度とデュプレックスが手動固定", f"{val} (実リンク {link})",
                "自動ネゴシエーション",
                "速度/デュプレックスを手動固定するとオートネゴシエーションが無効になる。\n"
                "相手側(ルータ/ハブ)が自動のままだと、相手はパラレルディテクトで速度しか\n"
                "判別できずデュプレックスを半二重と推定してしまう。これが古典的な\n"
                "**デュプレックスミスマッチ**で、衝突・遅延・TCP再送率の上昇を引き起こす。\n"
                f"実リンク速度({link})が設定値と食い違っている場合はとくに疑わしい。\n"
                "現代のGbE以上では手動固定に利点はないので、自動に戻すのが定石。",
                "Set-NetAdapterAdvancedProperty -Name \"{}\" -RegistryKeyword \"*SpeedDuplex\" "
                "-DisplayValue \"自動ネゴシエーション\"".format(sd.get("Name", ""))))

    # --- 3. 省電力設定 ---
    on = [(kw, POWER_SAVE_KEYWORDS[kw], adv[kw]) for kw in POWER_SAVE_KEYWORDS
          if kw in adv and is_enabled(adv[kw].get("DisplayValue")) is True]
    off = [POWER_SAVE_KEYWORDS[kw] for kw in POWER_SAVE_KEYWORDS
           if kw in adv and is_enabled(adv[kw].get("DisplayValue")) is False]
    if on:
        cmds = "\n".join(
            'Set-NetAdapterAdvancedProperty -Name "{}" -RegistryKeyword "{}" -DisplayValue "無効"'
            .format(row.get("Name", ""), kw) for kw, _t, row in on)
        out.append(_f(
            SEV_ADVISE, "省電力", "NICの省電力機能が有効",
            " / ".join(t for _k, t, _r in on), "すべて無効にして様子を見る",
            "これらはリンクのアイドル検出やケーブル長推定で消費電力を落とす機能。\n"
            "省電力状態から復帰する際にリンクが一瞬乱れることがあり、スイッチとの\n"
            "相性次第でパケットロス・TCP再送の増加として現れる。\n"
            "実害が出ているかは切り分けが必要なので「推奨」止まりだが、\n"
            "TCP再送率が高い環境では最初に無効化して比較する価値がある。\n\n"
            "・グリーンイーサネット / Power Saving Mode: Realtek独自の省電力。無効化推奨。\n"
            "・Gigabit Lite: 1Gbpsリンクの消費電力を落とす。リンク不安定の報告がある。\n"
            "・EEE (802.3az): リンクアイドル時に送受信を止める。相性問題が最も多い。\n\n"
            "※ 無効化しても速度の上限自体は変わらない。効くとすれば「再送が減る」方向。",
            cmds))
    if off:
        out.append(_f(SEV_INFO, "省電力", "無効化済みの省電力機能", " / ".join(off), "-",
                      "これらは既に無効。良好。"))

    # --- 4. デバイスの電源オフ (電源管理タブ) ---
    power = _as_list(ps.get("power"))
    if power:
        for p in power:
            allow = is_enabled(p.get("AllowComputerToTurnOffDevice"))
            if allow:
                out.append(_f(
                    SEV_ADVISE, "省電力", f"デバイスの電源オフが許可 ({p.get('Name')})",
                    "有効", "無効",
                    "「電力の節約のためにコンピューターでこのデバイスの電源をオフにできるようにする」\n"
                    "が有効。アイドル時にNICがD3状態へ落ち、復帰の瞬間に取りこぼしが起きうる。",
                    f'Disable-NetAdapterPowerManagement -Name "{p.get("Name")}" '
                    f'-AllowComputerToTurnOffDevice'))
            else:
                out.append(_f(SEV_INFO, "省電力", f"デバイスの電源オフ ({p.get('Name')})",
                              "無効", "無効", "アイドル時にNICの電源が落ちる設定にはなっていない。良好。"))
    else:
        # PnPCapabilities のビット 0x100 = NDIS_DEVICE_NO_PNP_CAPABILITIES。
        # これが立っているとドライバが電源管理非対応を宣言し、電源管理タブ自体が出ない。
        # Get-NetAdapterPowerManagement もエラー31を返すので、その説明を出す。
        caps = [c for c in _as_list(ps.get("pnpcap")) if c.get("PnPCapabilities") is not None]
        detail = ", ".join(f"{c['Desc']}=0x{int(c['PnPCapabilities']):X}" for c in caps) or "取得不可"
        no_pnp = any(int(c["PnPCapabilities"]) & 0x100 for c in caps)
        out.append(_f(
            SEV_INFO, "省電力", "デバイスの電源オフ設定", detail,
            "(問題なし)" if no_pnp else "確認",
            ("Get-NetAdapterPowerManagement は取得できなかったが、レジストリの PnPCapabilities に\n"
             "0x100 (NDIS_DEVICE_NO_PNP_CAPABILITIES) が立っている。ドライバが電源管理非対応を\n"
             "宣言しているため「電力の節約のためにデバイスの電源をオフにできる」設定は存在せず、\n"
             "アイドル時にNICの電源が落ちることはない。したがってこの項目は問題なし。"
             if no_pnp else
             "Get-NetAdapterPowerManagement を取得できなかった。デバイスマネージャの\n"
             "電源管理タブで手動確認のこと。") +
            (f"\n\n(採取時のエラー: {ps.get('power_error')})" if ps.get("power_error") else "")))

    # --- 5. TCP グローバルパラメータ ---
    tcp = data.get("netsh_tcp") or {}
    templates = {t.get("SettingName"): t for t in _as_list(ps.get("tcp"))}
    internet = templates.get("Internet") or templates.get("InternetCustom") or {}

    at = (tcp.get("autotuning") or internet.get("AutoTuningLevelLocal") or "").lower()
    if at in ("normal", "experimental"):
        out.append(_f(SEV_INFO, "TCP", "受信ウィンドウ自動チューニング", at or "-", "normal",
                      "normal が既定かつ推奨。受信ウィンドウを帯域遅延積に応じて自動拡大するため、\n"
                      "高遅延・高帯域の経路でもスループットが頭打ちにならない。"))
    elif at:
        out.append(_f(
            SEV_ACTION, "TCP", "受信ウィンドウ自動チューニングが制限されている", at, "normal",
            "自動チューニングを disabled / restricted / highlyrestricted にすると受信ウィンドウが\n"
            "64KB 前後に固定される。RTT 20ms なら約 26Mbps で頭打ちになる計算で、\n"
            "「回線契約は速いのに実測が出ない」の典型的な原因になる。\n"
            "古い高速化Tips記事で無効化を勧めるものがあるが、現在のWindowsでは有害。",
            "netsh int tcp set global autotuninglevel=normal"))

    cc = (tcp.get("congestion") or internet.get("CongestionProvider") or "").lower()
    if cc in ("cubic", "default"):
        actual = internet.get("CongestionProvider", "CUBIC")
        out.append(_f(SEV_INFO, "TCP", "輻輳制御プロバイダー",
                      f"{tcp.get('congestion', '-')} (Internetテンプレート: {actual})", "CUBIC",
                      "Windows 10 2004 以降の既定は CUBIC。Linux/主要サーバと同じアルゴリズムで、\n"
                      "高帯域経路での立ち上がりが速い。netsh の 'default' 表示は「アドオンなし=\n"
                      "テンプレートの設定に従う」の意味で、実体は Get-NetTCPSetting 側の値。"))
    elif cc:
        out.append(_f(SEV_ADVISE, "TCP", "輻輳制御プロバイダーが旧世代", cc, "CUBIC",
                      "NewReno / CTCP は CUBIC より帯域の使い切りが遅い。特に高帯域・中遅延の\n"
                      "経路でスループットが伸びにくい。",
                      "Set-NetTCPSetting -SettingName Internet -CongestionProvider CUBIC"))

    for key, good_val, why in [
        ("rss", "enabled",
         "受信処理を複数CPUコアに分散する。無効だと1コアがボトルネックになり、\n"
         "1Gbps超では取りこぼし(受信破棄)の原因になる。"),
        ("rsc", "enabled",
         "受信した複数セグメントをまとめてスタックへ渡し、CPU負荷を下げる。\n"
         "有効が既定。低遅延を極端に重視する用途でのみ無効化を検討する。"),
    ]:
        v = (tcp.get(key) or "").lower()
        if not v:
            continue
        ok = v.startswith(good_val)
        out.append(_f(SEV_INFO if ok else SEV_ADVISE, "TCP", NETSH_TITLE[key], tcp[key], good_val,
                      why if ok else why + "\n現在無効になっているため、有効化を検討。",
                      "" if ok else f"netsh int tcp set global "
                                    f"{'rss' if key == 'rss' else 'rsc'}=enabled"))

    if tcp.get("ecn"):
        out.append(_f(SEV_INFO, "TCP", "ECN 機能", tcp["ecn"], "disabled (既定のまま)",
                      "明示的輻輳通知。Windowsの既定は disabled。経路上に ECN を正しく扱えない\n"
                      "機器があると逆に接続不良を起こすため、意図的に有効化する理由がなければ\n"
                      "既定のままでよい。"))
    if tcp.get("timestamps"):
        out.append(_f(SEV_INFO, "TCP", "RFC 1323 タイムスタンプ", tcp["timestamps"], "allowed",
                      "RTT計測精度とPAWS(シーケンス番号の巻き戻り防止)に使う。allowed が既定。"))
    if tcp.get("initial_rto"):
        rto = _num(tcp["initial_rto"])
        out.append(_f(SEV_INFO, "TCP", "初期 RTO", f"{rto} ms", "1000 ms (既定)",
                      "SYN送信後、応答が無い場合に再送するまでの初期タイムアウト。\n"
                      "既定は1000ms。短くすると接続確立は速く見えるが、\n"
                      "遅延の大きい相手に対して不要な再送を撒くことになる。"))
    if internet.get("MinRto") is not None:
        out.append(_f(SEV_INFO, "TCP", "最小 RTO (Internetテンプレート)",
                      f"{internet['MinRto']} ms", "300 ms (既定)",
                      "再送タイムアウトの下限値。小さすぎると RTT のわずかな揺らぎで\n"
                      "偽の再送(spurious retransmission)が増え、再送率が実態より悪化する。"))
    for key in ("non_sack", "max_syn", "fast_open", "fast_open_fallback", "hystart", "prr", "pacing"):
        if tcp.get(key):
            out.append(_f(SEV_INFO, "TCP", NETSH_TITLE[key], tcp[key], "既定のまま",
                          "netsh int tcp show global の報告値。既定から外れていなければ触る必要はない。"))

    # --- 6. オフロード ---
    disabled_off = [(kw, OFFLOAD_KEYWORDS[kw], adv[kw]) for kw in OFFLOAD_KEYWORDS
                    if kw in adv and is_enabled(adv[kw].get("DisplayValue")) is False]
    enabled_off = [OFFLOAD_KEYWORDS[kw] for kw in OFFLOAD_KEYWORDS
                   if kw in adv and is_enabled(adv[kw].get("DisplayValue")) is True]
    if disabled_off:
        cmds = "\n".join(
            'Set-NetAdapterAdvancedProperty -Name "{}" -RegistryKeyword "{}" -DisplayValue "有効"'
            .format(row.get("Name", ""), kw) for kw, _t, row in disabled_off)
        out.append(_f(
            SEV_ADVISE, "オフロード", "オフロードが無効化されている",
            " / ".join(t for _k, t, _r in disabled_off), "既定(有効)に戻す",
            "チェックサム計算やセグメント分割をNICに肩代わりさせる機能。既定は有効。\n"
            "無効だとCPUがパケットごとに処理することになり、高スループット時の\n"
            "CPU負荷が上がる。ゲーム用の「低遅延化Tips」で無効化を勧める例があるが、\n"
            "数百Mbps以上を出す用途では逆効果になりうる。\n\n"
            "※ 300Mbps程度なら現代のCPUには余裕があるため、これが速度低下の主因である\n"
            "　 可能性は低い。既定に戻して比較する価値がある、という程度の位置づけ。",
            cmds))
    if enabled_off:
        out.append(_f(SEV_INFO, "オフロード", "有効なオフロード", " / ".join(enabled_off), "-",
                      "これらは既定どおり有効。"))

    rss_adv = adv.get("*RSS")
    if rss_adv:
        q = adv.get("*NumRssQueues", {}).get("DisplayValue", "?")
        en = is_enabled(rss_adv.get("DisplayValue"))
        out.append(_f(SEV_INFO if en else SEV_ADVISE, "オフロード", "受信側スケーリング (NIC側)",
                      f"{rss_adv.get('DisplayValue')} / キュー数 {q}", "有効",
                      "NIC側のRSS設定。グローバル設定が有効でもNIC側が無効だと分散されない。"
                      if en else "NIC側のRSSが無効。受信処理が1コアに集中する。",
                      "" if en else 'Set-NetAdapterAdvancedProperty -Name "{}" '
                                    '-RegistryKeyword "*RSS" -DisplayValue "有効"'
                                    .format(rss_adv.get("Name", ""))))

    im = adv.get("*InterruptModeration")
    if im:
        en = is_enabled(im.get("DisplayValue"))
        out.append(_f(SEV_INFO, "オフロード", "割込みモデレーション", im.get("DisplayValue"),
                      "有効 (既定)",
                      "割込みをまとめてCPU負荷を下げる機能。無効にすると遅延はわずかに下がるが\n"
                      "割込み回数が増える。低遅延重視の意図的な設定であればそのままでよい。"
                      if not en else "既定どおり有効。"))

    fc = adv.get("*FlowControl")
    if fc:
        out.append(_f(SEV_INFO, "オフロード", "フローコントロール", fc.get("DisplayValue"),
                      "無効でも可",
                      "802.3x PAUSEフレーム。有効だと輻輳時にリンク全体を止めてしまい\n"
                      "head-of-line blocking を起こすため、無効が推奨される場面も多い。"))

    # バッファ不足は「小さいこと」ではなく「溢れていること」で判定する。
    # 既定値が最大値よりずっと小さいドライバは普通にあるので、サイズだけを根拠に
    # 増設を勧めると根拠の薄い指摘になる。実際の破棄カウンタと突き合わせる。
    link = data.get("link") or {}
    # 自前の ps.stats を優先する。nd.get_link_stats() の adapters には
    # ReceivedUnicastPackets が含まれず、破棄の「割合」が出せないため。
    stats_rows = _as_list(ps.get("stats")) or _as_list(link.get("adapters"))
    rx_disc = sum(s.get("ReceivedDiscardedPackets") or 0 for s in stats_rows)
    rx_total = sum(s.get("ReceivedUnicastPackets") or 0 for s in stats_rows)
    tx_disc = sum(s.get("OutboundDiscardedPackets") or 0 for s in stats_rows)
    rx_overflow = bool(rx_total) and (rx_disc / rx_total * 100) >= DISCARD_WARN_PCT
    for kw, title, overflowing, counter in (
            ("*ReceiveBuffers", "受信バッファ", rx_overflow, "ReceivedDiscardedPackets"),
            ("*TransmitBuffers", "送信バッファ", tx_disc > 0, "OutboundDiscardedPackets")):
        row = adv.get(kw)
        if not row:
            continue
        cur = _num(row.get("DisplayValue"))
        mx = _num(row.get("NumericParameterMaxValue"))
        cur_s = f"{cur} (最大 {mx})" if mx else str(cur)
        small = bool(cur and mx and cur < mx * 0.5)
        if small and overflowing:
            out.append(_f(
                SEV_ADVISE, "NIC", f"{title}が不足している可能性", cur_s, f"{mx} (最大値)",
                f"{title}が設定可能な最大値の半分未満で、かつ {counter} が\n"
                "無視できない量まで増えている。バーストトラフィックでリングバッファが\n"
                "溢れている疑いがあるため、増やして破棄が減るか確認する価値がある。",
                'Set-NetAdapterAdvancedProperty -Name "{}" -RegistryKeyword "{}" '
                '-RegistryValue {}'.format(row.get("Name", ""), kw, mx)))
        else:
            why = (f"{title}は最大値付近まで確保されている。これ以上増やす余地はほぼない。"
                   if not small else
                   f"{title}はドライバ既定寄りの小さめの値だが、{counter} が増えていないため\n"
                   "実際には溢れていない。増やす根拠がないので現状維持でよい。")
            out.append(_f(SEV_INFO, "NIC", title, cur_s, "現状維持", why))

    # --- 7. 再送率・受信破棄 ---
    rt = link.get("tcp_retransmit_pct")
    if rt is not None:
        sev = (SEV_ACTION if rt >= RETRANS_ACTION_PCT else
               SEV_ADVISE if rt >= RETRANS_ADVISE_PCT else SEV_INFO)
        note = ("設定項目ではなく**症状**。原因は上記の省電力設定・デュプレックス固定・\n"
                "宅内配線・ISP側のいずれか。設定変更の前後でこの値を比較すると切り分けできる。\n"
                "なお netstat -s の値は OS 起動からの累計なので、過去の一時的な障害も含む。"
                if sev != SEV_INFO else "1%未満。正常な水準。")
        out.append(_f(sev, "統計", "TCP再送率", f"{rt}% "
                      f"({link.get('tcp_segments_retransmitted')} / "
                      f"{link.get('tcp_segments_sent')} セグメント)",
                      "1% 未満",
                      "TCP再送率が高いということは、送ったセグメントが途中で失われている。\n"
                      "帯域を再送に食われるうえ、輻輳制御が輻輳と判断して送信レートを絞るため\n"
                      "スループットが直接落ちる。\n" + note,
                      "netstat -s -p tcp"))

    for st in stats_rows:
        rx = st.get("ReceivedUnicastPackets")
        disc = st.get("ReceivedDiscardedPackets")
        errs = (st.get("ReceivedPacketErrors") or 0) + (st.get("OutboundPacketErrors") or 0)
        if disc is None:
            continue
        pct = (disc / rx * 100) if rx else None
        cur = f"{disc:,} 破棄" + (f" / {rx:,} 受信 = {pct:.4f}%" if pct is not None else "")
        if pct is not None and pct >= DISCARD_WARN_PCT:
            out.append(_f(SEV_ADVISE, "統計", f"受信破棄が多い ({st.get('Name')})", cur,
                          f"{DISCARD_WARN_PCT}% 未満",
                          "受信リングバッファ溢れやRSS不足で取りこぼしている。\n"
                          "受信バッファ増加とRSS有効化で改善することがある。"))
        else:
            out.append(_f(SEV_INFO, "統計", f"受信破棄 ({st.get('Name')})", cur,
                          f"{DISCARD_WARN_PCT}% 未満",
                          "受信パケット総数に対する破棄の割合はごくわずかで、実害のある水準ではない。\n"
                          "絶対数だけを見ると多く感じるが、割合で見ると無視できる。"
                          if pct is not None else "受信総数が取れなかったため割合は未算出。"))
        out.append(_f(SEV_INFO if errs == 0 else SEV_ADVISE, "統計",
                      f"NICハードウェアエラー ({st.get('Name')})", f"{errs} 件", "0 件",
                      "CRCエラー等の物理層エラー。0件ならケーブル・ポート・コネクタは健全。\n"
                      "ここが0なのに再送率が高いなら、原因は宅内の物理層より外側にある。"
                      if errs == 0 else "物理層でエラーが出ている。ケーブル/ポートの交換を検討。"))

    # --- 8. DNS クライアント ---
    n = ps.get("dns_cache_count")
    if n is not None:
        out.append(_f(SEV_INFO, "DNS", "DNSキャッシュ件数", f"{n} 件", "-",
                      "名前解決の結果をOSがキャッシュしている件数。名前解決が遅い症状の\n"
                      "切り分けでは、一度クリアしてから再現するか確認する。",
                      "ipconfig /flushdns"))
    for s in _as_list(ps.get("dns_servers")):
        fam = {2: "IPv4", 23: "IPv6"}.get(s.get("AddressFamily"), s.get("AddressFamily"))
        if str(s.get("InterfaceAlias", "")).lower().startswith("loopback"):
            continue
        out.append(_f(SEV_INFO, "DNS", f"DNSサーバ ({s.get('InterfaceAlias')} / {fam})",
                      s.get("Servers"), "-",
                      "ルータのアドレスならルータのDNSフォワーダ経由。応答が遅い場合は\n"
                      "1.1.1.1 / 8.8.8.8 を直接指定して比較すると切り分けできる。\n"
                      "ただしIPv6経由のIPoE環境ではISP側DNSのほうが速いことも多い。"))
    for nb in _as_list(ps.get("netbios")):
        opt = nb.get("TcpipNetbiosOptions")
        label = {0: "DHCPの既定に従う", 1: "有効", 2: "無効"}.get(opt, str(opt))
        out.append(_f(SEV_INFO, "DNS", "NetBIOS over TCP/IP", label, "無効 (2)",
                      "レガシーな名前解決。無効にすると名前解決失敗時の余計な\n"
                      "ブロードキャストが減るが、速度への影響はごくわずか。\n"
                      "共有フォルダを古い機器と使っていないなら無効化してよい。"))
    llmnr = ps.get("llmnr")
    out.append(_f(SEV_INFO, "DNS", "LLMNR",
                  "無効 (ポリシーで抑止)" if llmnr == 0 else "有効 (既定)", "-",
                  "マルチキャストによるローカル名前解決。DNSで引けない名前について\n"
                  "余計なマルチキャストを撒くが、通常の通信速度には影響しない。"))
    mdns = ps.get("mdns")
    out.append(_f(SEV_INFO, "DNS", "mDNS", "無効" if mdns == 0 else "有効 (既定)", "-",
                  ".local 名の解決に使う。Chromecast等の検出に必要。"))

    # --- 9. QoS / プロファイル / 配信の最適化 ---
    qos = _as_list(ps.get("qos"))
    if qos:
        for q in qos:
            thr = q.get("ThrottleRateActionBitsPerSecond")
            sev = SEV_ADVISE if thr else SEV_INFO
            out.append(_f(sev, "QoS", f"QoSポリシー: {q.get('Name')}",
                          f"帯域制限 {thr} bps" if thr else "優先度指定のみ", "-",
                          "帯域制限つきのQoSポリシーがある。意図しないものなら速度低下の直接原因。"
                          if thr else "QoSポリシーが設定されている。帯域制限は含まれていない。",
                          f'Get-NetQosPolicy -Name "{q.get("Name")}"'))
    else:
        out.append(_f(SEV_INFO, "QoS", "QoSポリシー", "なし", "-",
                      "帯域を絞るQoSポリシーは設定されていない。速度低下の原因にはなっていない。"))

    for p in _as_list(ps.get("profiles")):
        out.append(_f(SEV_INFO, "その他", f"ネットワークプロファイル ({p.get('InterfaceAlias')})",
                      f"{p.get('NetworkCategory')} / IPv4:{p.get('IPv4Connectivity')} "
                      f"IPv6:{p.get('IPv6Connectivity')}", "-",
                      "パブリックはファイアウォールが厳しく、ネットワーク探索が無効になる。\n"
                      "宅内LANの共有機能を使うならプライベートにする。速度自体には影響しない。"))

    do = ps.get("delivery")
    if isinstance(do, dict):
        mode = do.get("DownloadMode")
        label = DO_MODES.get(mode, str(mode))
        if mode in DO_P2P:
            out.append(_f(SEV_ADVISE, "その他", "Windows Update 配信の最適化 (P2P)", label,
                          "CdnOnly (P2Pなし)",
                          "他PCへの配信で上り帯域を消費する。特に「インターネット越しにP2P」は\n"
                          "見知らぬPCへ更新ファイルをアップロードするため上りを食う。",
                          "設定 > Windows Update > 詳細オプション > 配信の最適化 で\n"
                          "「他のPCからのダウンロードを許可する」をオフ"))
        else:
            out.append(_f(SEV_INFO, "その他", "Windows Update 配信の最適化", label,
                          "CdnOnly (P2Pなし)",
                          "P2P配信は行わない設定。他PCへのアップロードで上り帯域を食うことはない。\n"
                          f"(上り上限 {do.get('MaxUploadRatePct')}% / "
                          f"月間 {do.get('UploadLimitMonthlyGB')}GB — P2P無効なので未使用)"))

    # ---- ドライバ更新 ----
    wu = data.get("wu") or {}
    state, detail = driver_update_state(wu)
    if state == "available":
        titles = "\n".join(f"・{d.get('Title')}" for d in _as_list(wu.get("drivers")))
        out.append(_f(SEV_ADVISE, "ドライバ", "Windows Update に未適用のドライバがある", detail,
                      "内容を確認して適用",
                      f"Windows Update が配信しているドライバ更新:\n{titles}\n\n"
                      "ネットワーク関連が含まれる場合は速度・安定性に直接効くことがある。\n"
                      "ドライバ更新は不具合を持ち込むこともあるので、適用前に復元ポイントを作ると安全。",
                      "設定 > Windows Update > 詳細オプション > オプションの更新プログラム"))
    elif state == "suppressed":
        out.append(_f(SEV_ADVISE, "ドライバ", "ドライバ更新の確認が抑止されている", detail,
                      "抑止を解除して確認する",
                      "この設定のため Windows Update からドライバ更新が降ってこない。\n"
                      "「更新が無い」ではなく「確認できない」状態なので、NICのドライバは\n"
                      "メーカー配布ページで直接確認する必要がある。"))
    elif state == "unknown":
        out.append(_f(SEV_INFO, "ドライバ", "ドライバ更新を確認できなかった", detail, "-",
                      "Windows Update への問い合わせが失敗した。\n"
                      "この項目は判定から除外している(「最新」とは言えない)。"))
    else:
        proof = ("ただし未適用の更新が他にも0件のため、検索機構が実際に動いていることまでは\n"
                 "確認できていない。この結果だけで「最新」と判断しない。\n"
                 if state == "none_unproven" else
                 f"(非ドライバの未適用更新が{_num(wu.get('other_count'))}件返っており、"
                 "検索機構は動作している)\n")
        out.append(_f(SEV_INFO, "ドライバ", "Windows Update のドライバ更新", detail, "-",
                      "Windows Update には未適用のドライバが無い。\n" + proof +
                      "なお Windows Update が配信するのはWHQL署名済みの版のみで、\n"
                      "メーカー配布の最新版より古いことが普通にある。リンク速度がNICの上限に\n"
                      "届いていない場合はメーカー配布版を確認する価値がある。"))

    for a in adapters:
        age = _driver_age_days(a.get("DriverDate"))
        drv_note = f" / 更新から約{age // 365}年{(age % 365) // 30}か月" if age is not None else ""
        out.append(_f(SEV_INFO, "NIC", f"リンク状態 ({a.get('Name')})",
                      f"{a.get('LinkSpeed')} / "
                      f"{'全二重' if a.get('FullDuplex') else '半二重'} / MTU {a.get('MtuSize')}",
                      "-",
                      f"{a.get('InterfaceDescription')}\n"
                      f"ドライバ {a.get('DriverVersion')}{drv_note}\n"
                      "半二重になっている場合はオートネゴシエーションの失敗を疑う。"))

    for e in data.get("errors") or []:
        out.append(_f(SEV_INFO, "採取", "採取エラー", e, "-", "この項目は判定から除外されている。"))

    out.sort(key=lambda f: f["sev"])  # 同一重大度内は追加順(Pythonのsortは安定)
    return out


def summarize(findings):
    """総合判定の1行サマリ。"""
    n_act = sum(1 for f in findings if f["sev"] == SEV_ACTION)
    n_adv = sum(1 for f in findings if f["sev"] == SEV_ADVISE)
    if not n_act and not n_adv:
        return "問題は検出されませんでした", "good"
    parts = []
    if n_act:
        parts.append(f"要対処 {n_act} 件")
    if n_adv:
        parts.append(f"推奨 {n_adv} 件")
    return " / ".join(parts) + f"  (情報 {len(findings) - n_act - n_adv} 件)", \
        "bad" if n_act else "warn"


# ---------- タブ本体 ----------

COLUMNS = [("sev", "重大度", 70), ("cat", "分類", 90), ("item", "項目", 300),
           ("current", "現在値", 260), ("recommend", "推奨値", 190)]


class TuningTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.findings = []
        self.data = None
        self._thread = None
        self._stop = threading.Event()

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        self.run_btn = ttk.Button(top, text="🔍  監査を実行", style="Accent.TButton", command=self.start)
        self.run_btn.pack(side="left", padx=(0, 8))
        self.copy_btn = ttk.Button(top, text="⧉  コマンドをコピー", command=self.copy_command,
                                   state="disabled")
        self.copy_btn.pack(side="left", padx=4)
        ttk.Button(top, text="⬇  JSON", command=self.export).pack(side="left", padx=4)
        self.only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="要対処・推奨のみ表示", variable=self.only_var,
                        command=self._render).pack(side="left", padx=(16, 0))
        ttk.Label(top, text="※ 読み取り専用。設定は変更しません").pack(side="right")

        self.status = ttk.Label(parent, text="未実行  —  「監査を実行」を押してください", padding=(6, 4))
        self.status.pack(fill="x")

        pane = ttk.PanedWindow(parent, orient="vertical")
        pane.pack(fill="both", expand=True, padx=4, pady=(4, 8))

        tree_wrap = ttk.Frame(pane)
        self.tree = ttk.Treeview(tree_wrap, columns=[c[0] for c in COLUMNS], show="headings", height=14)
        for key, head, width in COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width, anchor="w", stretch=key in ("item", "current"))
        sb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_detail())
        pane.add(tree_wrap, weight=3)

        detail_wrap = ttk.Frame(pane)
        self.detail = tk.Text(detail_wrap, height=12, wrap="word", relief="flat",
                              padx=10, pady=8, font=(ctx.font, 10))
        dsb = ttk.Scrollbar(detail_wrap, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=dsb.set, state="disabled")
        self.detail.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        pane.add(detail_wrap, weight=2)

        self.on_theme_changed()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        for sev, tag in SEV_TAG.items():
            self.tree.tag_configure(f"sev{sev}", foreground=t[tag])
        # sv_ttk が Treeview の style.map に -foreground を入れており、そのままだと
        # tag_configure の色が無視される。選択状態以外のマッピングを外してタグ色を優先させる。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.detail.configure(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"],
                              selectbackground=t["muted"])
        self.detail.tag_configure("h", foreground=t["fg"], font=(self.ctx.font, 11, "bold"))
        self.detail.tag_configure("key", foreground=t["muted"])
        self.detail.tag_configure("cmd", foreground=t["good"], font=("Consolas", 10))
        for sev, tag in SEV_TAG.items():
            self.detail.tag_configure(f"sev{sev}", foreground=t[tag],
                                      font=(self.ctx.font, 11, "bold"))
        self.status.config(foreground=t["muted"])
        self._show_detail()

    # ---- 実行 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.run_btn.config(state="disabled")
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        def progress(msg):
            if not self._stop.is_set():
                self.ctx.root.after(0, lambda: self.status.config(
                    text=msg, foreground=self.ctx.theme["muted"]))

        try:
            data = collect(progress)
            findings = analyze(data)
        except Exception as e:
            err = f"監査に失敗: {e}"
            self.ctx.root.after(0, lambda: self._done(None, [], err))
            return
        if not self._stop.is_set():
            self.ctx.root.after(0, lambda: self._done(data, findings, None))

    def _done(self, data, findings, error):
        self.run_btn.config(state="normal")
        if error:
            self.status.config(text=error, foreground=self.ctx.theme["bad"])
            return
        self.data, self.findings = data, findings
        self._render()

    # ---- 表示 ----

    def _render(self):
        self.tree.delete(*self.tree.get_children())
        # iid には findings のインデックスをそのまま使う。index(f) で引くと
        # 内容が完全に同じ所見が2件あったとき iid が衝突して insert が失敗する。
        rows = [(i, f) for i, f in enumerate(self.findings)
                if not self.only_var.get() or f["sev"] != SEV_INFO]
        for i, f in rows:
            self.tree.insert("", "end", iid=str(i),
                             values=(SEV_LABEL[f["sev"]], f["cat"], f["item"],
                                     f["current"], f["recommend"]),
                             tags=(f"sev{f['sev']}",))
        if self.findings:
            text, tone = summarize(self.findings)
            when = (self.data or {}).get("timestamp", "")
            self.status.config(text=f"{text}   [{when}]", foreground=self.ctx.theme[tone])
            if rows:
                self.tree.selection_set(self.tree.get_children()[0])
            else:
                self._show_detail()

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return self.findings[int(sel[0])]
        except (ValueError, IndexError):
            return None

    def _show_detail(self):
        f = self._selected()
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        if not f:
            self.detail.insert("end",
                               "監査を実行すると、検出項目が重大度順に並びます。\n"
                               "行を選ぶと、ここに「なぜ問題か」と「変更コマンド」が出ます。\n\n"
                               "このタブは読み取り専用です。コマンドは表示するだけで実行しません。",
                               "key")
            self.detail.config(state="disabled")
            self.copy_btn.config(state="disabled")
            return
        self.detail.insert("end", f"[{SEV_LABEL[f['sev']]}] ", f"sev{f['sev']}")
        self.detail.insert("end", f"{f['cat']} / {f['item']}\n\n", "h")
        self.detail.insert("end", "現在値: ", "key")
        self.detail.insert("end", f"{f['current']}\n")
        self.detail.insert("end", "推奨値: ", "key")
        self.detail.insert("end", f"{f['recommend']}\n\n")
        self.detail.insert("end", "なぜそう推奨するか\n", "key")
        self.detail.insert("end", f"{f['why']}\n")
        if f["cmd"]:
            self.detail.insert("end", "\n変更するためのコマンド (管理者権限。表示のみ・自動実行はしません)\n", "key")
            self.detail.insert("end", f"{f['cmd']}\n", "cmd")
        self.detail.config(state="disabled")
        self.copy_btn.config(state="normal" if f["cmd"] else "disabled")

    def copy_command(self):
        f = self._selected()
        if not f or not f["cmd"]:
            return
        self.ctx.root.clipboard_clear()
        self.ctx.root.clipboard_append(f["cmd"])
        self.status.config(text="✓ コマンドをクリップボードにコピーしました",
                           foreground=self.ctx.theme["good"])

    def export(self):
        if not self.findings:
            self.status.config(text="エクスポートするデータがありません",
                               foreground=self.ctx.theme["warn"])
            return
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"tuning_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        summary, _tone = summarize(self.findings)
        path.write_text(json.dumps({
            "timestamp": (self.data or {}).get("timestamp"),
            "summary": summary,
            "findings": [dict(f, sev_label=SEV_LABEL[f["sev"]]) for f in self.findings],
            "raw": {k: v for k, v in (self.data or {}).items() if k != "netsh_raw"},
        }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        self.status.config(text=f"✓ 出力: {path.name}", foreground=self.ctx.theme["good"])

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


# ---------- 自己テスト (ネットワーク不要) ----------

# 実機 (Windows 11 / 日本語 / Realtek Gaming 2.5GbE) から採取した本物の出力。
SAMPLE_NETSH_GLOBAL = (
    "アクティブ状態を照会しています...\r\n\r\nTCP グローバル パラメーター\r\n"
    "----------------------------------------------\r\n"
    "Receive-Side Scaling 状態          : enabled \r\n"
    "受信ウィンドウ自動チューニング レベル    : normal \r\n"
    "アドオン輻輳制御プロバイダー  : default \r\n"
    "ECN 機能                      : disabled \r\n"
    "RFC 1323 タイムスタンプ                 : allowed \r\n"
    "初期 RTO                         : 1000 \r\n"
    "Receive Segment Coalescing 状態    : enabled \r\n"
    "非 Sack の Rtt 回復性             : disabled \r\n"
    "SYN の最大再送信数             : 4 \r\n"
    "Fast Open                           : enabled \r\n"
    "Fast Open フォールバック                  : enabled \r\n"
    "HyStart                             : enabled \r\n"
    "Proportional Rate Reduction         : enabled \r\n"
    "ペーシング プロファイル                      : off \r\n\r\n"
)

SAMPLE_NETSH_GLOBAL_EN = (
    "Querying active state...\r\n\r\nTCP Global Parameters\r\n"
    "----------------------------------------------\r\n"
    "Receive-Side Scaling State          : enabled \r\n"
    "Receive Window Auto-Tuning Level    : normal \r\n"
    "Add-On Congestion Control Provider  : default \r\n"
    "ECN Capability                      : disabled \r\n"
    "RFC 1323 Timestamps                 : allowed \r\n"
    "Initial RTO                         : 1000 \r\n"
    "Receive Segment Coalescing State    : enabled \r\n"
    "Fast Open                           : enabled \r\n"
    "Fast Open Fallback                  : enabled \r\n"
    "Pacing Profile                      : off \r\n\r\n"
)

SAMPLE_SUBIF = (
    "\r\n       MTU  MediaSenseState      バイト イン     バイト アウト  インターフェイス\r\n"
    "----------  ---------------  ------------  ------------  -------------\r\n"
    "4294967295                1             0         70334  Loopback Pseudo-Interface 1\r\n"
    "      1500                1   15905375261    8869487792  イーサネット\r\n\r\n"
)

SAMPLE_PING_OK = (
    "\r\n1.1.1.1 に ping を送信しています 1432 バイトのデータ:\r\n"
    "1.1.1.1 からの応答: バイト数 =1432 時間 =7ms TTL=59\r\n"
)
SAMPLE_PING_FRAG = (
    "\r\n1.1.1.1 に ping を送信しています 1433 バイトのデータ:\r\n"
    "192.168.3.1 からの応答: パケットの断片化が必要ですが、DF が設定されています。\r\n"
)
SAMPLE_PING_LOCAL_FRAG = (
    "\r\n1.1.1.1 に ping を送信しています 1472 バイトのデータ:\r\n"
    "パケットの断片化が必要ですが、DF が設定されています。\r\n"
)
SAMPLE_PING_TIMEOUT = (
    "\r\n1.1.1.1 に ping を送信しています 1473 バイトのデータ:\r\n"
    "要求がタイムアウトしました。\r\n"
)


def _base_data(**over):
    """判定テスト用の最小データ。上書きしたいキーだけ渡す。"""
    d = {
        "ps": {
            "adapters": {"Name": "イーサネット", "Status": "Up", "LinkSpeed": "1 Gbps",
                         "FullDuplex": True, "MtuSize": 1500,
                         "InterfaceDescription": "Realtek Gaming 2.5GbE Family Controller"},
            "advanced": [], "power": [], "pnpcap": [], "tcp": [], "profiles": [],
            "dns_servers": [], "netbios": [], "qos": None, "stats": None,
        },
        "netsh_tcp": parse_netsh_tcp_global(SAMPLE_NETSH_GLOBAL),
        "subif4": parse_subinterfaces(SAMPLE_SUBIF), "subif6": [],
        "path_mtu": {"mtu": 1460, "max_payload": 1432, "interpretation": "IPv4 over IPv6"},
        "pmtud": "ok", "link": {}, "errors": [],
    }
    d.update(over)
    return d


def _find(findings, needle):
    return [f for f in findings if needle in f["item"]]


def _selftest():
    # --- netsh パース: 日本語 ---
    g = parse_netsh_tcp_global(SAMPLE_NETSH_GLOBAL)
    assert g["autotuning"] == "normal", g
    assert g["congestion"] == "default", g
    assert g["rss"] == "enabled" and g["rsc"] == "enabled", g
    assert g["ecn"] == "disabled" and g["timestamps"] == "allowed", g
    assert g["initial_rto"] == "1000" and g["max_syn"] == "4", g
    assert g["pacing"] == "off" and g["hystart"] == "enabled", g
    # 部分文字列の罠: 「Fast Open」が「Fast Open フォールバック」を巻き込んでいないこと
    assert g["fast_open"] == "enabled" and g["fast_open_fallback"] == "enabled", g
    assert len(g) == 14, g
    # 「Receive-Side Scaling 状態」と「Receive Segment Coalescing 状態」も別物として拾えている
    assert set(g) >= {"rss", "rsc"}, g

    # --- netsh パース: 英語 ---
    e = parse_netsh_tcp_global(SAMPLE_NETSH_GLOBAL_EN)
    assert e["autotuning"] == "normal" and e["rss"] == "enabled", e
    assert e["fast_open"] == "enabled" and e["fast_open_fallback"] == "enabled", e
    assert "hystart" not in e, e

    assert parse_netsh_tcp_global("") == {}
    assert parse_netsh_tcp_global("ゴミ行\n----\n") == {}

    # --- subinterfaces パース (ループバック除外・空白入り名) ---
    rows = parse_subinterfaces(SAMPLE_SUBIF)
    assert rows == [{"name": "イーサネット", "mtu": 1500}], rows
    assert parse_subinterfaces("") == []

    # --- PMTUD 判定 ---
    assert classify_pmtud(SAMPLE_PING_OK) == "passed"
    assert classify_pmtud(SAMPLE_PING_FRAG) == "ok"
    assert classify_pmtud(SAMPLE_PING_LOCAL_FRAG) == "ok"
    assert classify_pmtud(SAMPLE_PING_TIMEOUT) == "blackhole"
    assert classify_pmtud("Reply from 10.0.0.1: Packet needs to be fragmented but DF set.") == "ok"
    assert classify_pmtud("Request timed out.") == "blackhole"
    assert classify_pmtud("Reply from 1.1.1.1: bytes=1432 time=7ms TTL=59") == "passed"
    assert classify_pmtud("") == "unknown"

    # --- 値の正規化 ---
    assert is_enabled("有効") is True and is_enabled("無効") is False
    assert is_enabled("受信と伝送有効") is True      # 複合値でも 有効 を拾う
    assert is_enabled("Rx & Tx Enabled") is True
    assert is_enabled("Disabled") is False and is_enabled("Enabled") is True
    assert is_enabled("2.5 Gbps フルデュプレックス") is None
    assert is_enabled(None) is None
    assert _as_list(None) == [] and _as_list({"a": 1}) == [{"a": 1}] and _as_list([1, 2]) == [1, 2]
    assert _num("488") == 488 and _num("2キュー") == 2 and _num("") is None
    assert _num(0) == 0 and _num("0") == 0, "整数の0を値なし扱いにしてはいけない"
    assert _num(None) is None

    # --- MTU 不整合の判定 ---
    ok = analyze(_base_data(pmtud="ok"))
    m = _find(ok, "MTU不一致 (PMTUD正常)")
    assert len(m) == 1 and m[0]["sev"] == SEV_INFO, m
    assert "1500" in m[0]["current"] and "1460" in m[0]["current"], m

    bh = analyze(_base_data(pmtud="blackhole"))
    m = _find(bh, "PMTUDブラックホール")
    assert len(m) == 1 and m[0]["sev"] == SEV_ACTION, m
    assert "mtu=1460" in m[0]["cmd"], m[0]["cmd"]

    unk = analyze(_base_data(pmtud="unknown"))
    assert _find(unk, "MTU不一致 (PMTUD未確認)")[0]["sev"] == SEV_ADVISE

    # インタフェースMTUが経路MTU以下なら不整合なし
    aligned = analyze(_base_data(subif4=[{"name": "イーサネット", "mtu": 1454}]))
    assert _find(aligned, "MTU整合")[0]["sev"] == SEV_INFO
    assert not _find(aligned, "PMTUDブラックホール")

    # --- 速度とデュプレックス ---
    forced = _base_data()
    forced["ps"]["advanced"] = [{"Name": "イーサネット", "RegistryKeyword": "*SpeedDuplex",
                                 "DisplayValue": "2.5 Gbps フルデュプレックス"}]
    r = _find(analyze(forced), "速度とデュプレックスが手動固定")
    assert len(r) == 1 and r[0]["sev"] == SEV_ACTION, r
    auto = _base_data()
    auto["ps"]["advanced"] = [{"Name": "イーサネット", "RegistryKeyword": "*SpeedDuplex",
                               "DisplayValue": "自動ネゴシエーション"}]
    r = _find(analyze(auto), "速度とデュプレックス")
    assert len(r) == 1 and r[0]["sev"] == SEV_INFO, r

    # --- 省電力 ---
    pw = _base_data()
    pw["ps"]["advanced"] = [
        {"Name": "イーサネット", "RegistryKeyword": "EnableGreenEthernet", "DisplayValue": "有効"},
        {"Name": "イーサネット", "RegistryKeyword": "PowerSavingMode", "DisplayValue": "有効"},
        {"Name": "イーサネット", "RegistryKeyword": "*EEE", "DisplayValue": "無効"},
    ]
    r = _find(analyze(pw), "NICの省電力機能が有効")
    assert len(r) == 1 and r[0]["sev"] == SEV_ADVISE, r
    assert "グリーンイーサネット" in r[0]["current"] and "Power Saving Mode" in r[0]["current"], r
    assert "EEE" not in r[0]["current"], r      # 無効なものは巻き込まない
    assert _find(analyze(pw), "無効化済みの省電力機能")[0]["current"] == "省電力型イーサネット (EEE)"

    # 全部無効なら「要対処/推奨」を出さない
    allo = _base_data()
    allo["ps"]["advanced"] = [{"Name": "イーサネット", "RegistryKeyword": k, "DisplayValue": "無効"}
                              for k in ("EnableGreenEthernet", "PowerSavingMode", "*EEE")]
    assert not _find(analyze(allo), "NICの省電力機能が有効")

    # --- PnPCapabilities 0x100 の解釈 ---
    np_ = _base_data()
    np_["ps"]["pnpcap"] = [{"Desc": "Realtek", "PnPCapabilities": 256}]
    r = _find(analyze(np_), "デバイスの電源オフ設定")
    assert len(r) == 1 and r[0]["sev"] == SEV_INFO and "問題なし" in r[0]["recommend"], r

    # --- 自動チューニング ---
    for lvl, sev in [("normal", SEV_INFO), ("disabled", SEV_ACTION),
                     ("highlyrestricted", SEV_ACTION), ("restricted", SEV_ACTION)]:
        d = _base_data()
        d["netsh_tcp"] = dict(d["netsh_tcp"], autotuning=lvl)
        got = [f for f in analyze(d) if "自動チューニング" in f["item"]]
        assert len(got) == 1 and got[0]["sev"] == sev, (lvl, got)

    # --- 輻輳制御 ---
    d = _base_data()
    d["netsh_tcp"] = dict(d["netsh_tcp"], congestion="NewReno")
    assert _find(analyze(d), "輻輳制御プロバイダーが旧世代")[0]["sev"] == SEV_ADVISE
    assert _find(analyze(_base_data()), "輻輳制御プロバイダー")[0]["sev"] == SEV_INFO

    # --- オフロード ---
    of = _base_data()
    of["ps"]["advanced"] = [
        {"Name": "イーサネット", "RegistryKeyword": "*LsoV2IPv4", "DisplayValue": "無効"},
        {"Name": "イーサネット", "RegistryKeyword": "*TCPChecksumOffloadIPv4",
         "DisplayValue": "受信と伝送有効"},
    ]
    r = analyze(of)
    assert _find(r, "オフロードが無効化されている")[0]["sev"] == SEV_ADVISE
    assert "一括送信オフロード v2 (IPv4)" in _find(r, "オフロードが無効化")[0]["current"]
    assert "TCP チェックサムオフロード (IPv4)" in _find(r, "有効なオフロード")[0]["current"]

    # --- バッファは「小さいこと」ではなく「溢れていること」で判定する ---
    def _buf(display, disc, rx=1_000_000):
        d = _base_data(link={"adapters": [{"Name": "イーサネット", "ReceivedUnicastPackets": rx,
                                           "ReceivedDiscardedPackets": disc,
                                           "ReceivedPacketErrors": 0, "OutboundPacketErrors": 0}]})
        d["ps"]["advanced"] = [{"Name": "イーサネット", "RegistryKeyword": "*ReceiveBuffers",
                                "DisplayValue": display, "NumericParameterMaxValue": "512"}]
        return analyze(d)

    assert _find(_buf("488", 0), "受信バッファ")[0]["sev"] == SEV_INFO        # 最大値付近
    # 小さくても破棄が出ていなければ指摘しない (根拠の薄い指摘を出さない)
    r = _find(_buf("64", 0), "受信バッファ")
    assert len(r) == 1 and r[0]["sev"] == SEV_INFO, r
    assert not _find(_buf("64", 0), "不足している可能性")
    # 小さく、かつ破棄が出ていれば初めて推奨
    r = _find(_buf("64", 50_000), "受信バッファが不足している可能性")
    assert len(r) == 1 and r[0]["sev"] == SEV_ADVISE, r
    # 大きいのに破棄が出ている場合はバッファのせいにしない
    assert not _find(_buf("488", 50_000), "不足している可能性")

    # 送信バッファ: OutboundDiscardedPackets が 0 なら小さくても情報扱い
    tx = _base_data(link={"adapters": [{"Name": "イーサネット", "ReceivedUnicastPackets": 1000,
                                        "ReceivedDiscardedPackets": 0, "OutboundDiscardedPackets": 0,
                                        "ReceivedPacketErrors": 0, "OutboundPacketErrors": 0}]})
    tx["ps"]["advanced"] = [{"Name": "イーサネット", "RegistryKeyword": "*TransmitBuffers",
                             "DisplayValue": "128", "NumericParameterMaxValue": "4096"}]
    r = _find(analyze(tx), "送信バッファ")
    assert len(r) == 1 and r[0]["sev"] == SEV_INFO, r
    tx["link"]["adapters"][0]["OutboundDiscardedPackets"] = 900
    assert _find(analyze(tx), "送信バッファが不足している可能性")[0]["sev"] == SEV_ADVISE

    # --- 再送率 ---
    for pct, sev in [(0.4, SEV_INFO), (1.5, SEV_ADVISE), (3.6, SEV_ACTION)]:
        d = _base_data(link={"tcp_retransmit_pct": pct, "tcp_segments_sent": 1000,
                             "tcp_segments_retransmitted": int(pct * 10)})
        assert _find(analyze(d), "TCP再送率")[0]["sev"] == sev, (pct, sev)

    # --- 受信破棄は「割合」で判定する (絶対数が大きくても率が低ければ情報扱い) ---
    d = _base_data(link={"adapters": [{"Name": "イーサネット", "ReceivedUnicastPackets": 56_537_924,
                                       "ReceivedDiscardedPackets": 52605,
                                       "ReceivedPacketErrors": 0, "OutboundPacketErrors": 0}]})
    r = _find(analyze(d), "受信破棄")
    assert len(r) == 1 and r[0]["sev"] == SEV_INFO, r      # 0.093% < 0.1%
    d["link"]["adapters"][0]["ReceivedDiscardedPackets"] = 500_000
    assert _find(analyze(d), "受信破棄が多い")[0]["sev"] == SEV_ADVISE

    # --- 配信の最適化 ---
    for mode, sev in [(0, SEV_INFO), (1, SEV_ADVISE), (3, SEV_ADVISE), (99, SEV_INFO)]:
        d = _base_data()
        d["ps"]["delivery"] = {"DownloadMode": mode, "MaxUploadRatePct": 5,
                               "UploadLimitMonthlyGB": 5}
        got = [f for f in analyze(d) if "配信の最適化" in f["item"]]
        assert len(got) == 1 and got[0]["sev"] == sev, (mode, got)

    # --- QoS ---
    d = _base_data()
    d["ps"]["qos"] = {"Name": "制限", "ThrottleRateActionBitsPerSecond": 10_000_000}
    assert _find(analyze(d), "QoSポリシー: 制限")[0]["sev"] == SEV_ADVISE
    assert _find(analyze(_base_data()), "QoSポリシー")[0]["sev"] == SEV_INFO

    # --- 優先度順の並び + 総合判定 ---
    mixed = analyze(_base_data(pmtud="blackhole",
                               link={"tcp_retransmit_pct": 3.6, "tcp_segments_sent": 1000,
                                     "tcp_segments_retransmitted": 36}))
    sevs = [f["sev"] for f in mixed]
    assert sevs == sorted(sevs), sevs
    assert sevs[0] == SEV_ACTION
    text, tone = summarize(mixed)
    assert "要対処" in text and tone == "bad", (text, tone)

    clean = [f for f in analyze(_base_data()) if f["sev"] == SEV_INFO]
    text, tone = summarize(clean)
    assert text == "問題は検出されませんでした" and tone == "good", (text, tone)
    assert summarize([])[0] == "問題は検出されませんでした"
    text, tone = summarize([_f(SEV_ADVISE, "x", "y", "1", "2", "3")])
    assert tone == "warn" and "推奨 1 件" in text, (text, tone)

    # --- 全所見が契約どおりのキーを持つこと ---
    for f in mixed:
        assert set(f) == {"sev", "cat", "item", "current", "recommend", "why", "cmd"}, f
        assert f["sev"] in SEV_LABEL and f["why"], f

    # ドライバ更新: 「確認できていない」を「0件=最新」に混ぜないこと。
    # ここを取り違えると、古いドライバのまま「最新です」と報告することになる。
    assert driver_update_state(None)[0] == "unknown"
    assert driver_update_state({"error": "RPC失敗"})[0] == "unknown"
    assert driver_update_state({"wsus": "http://wsus.local", "drivers": []})[0] == "suppressed"
    assert driver_update_state({"search_order": 0, "drivers": []})[0] == "suppressed"
    assert driver_update_state({"exclude_wu_drivers": 1, "drivers": []})[0] == "suppressed"
    assert driver_update_state({"drivers": [{"Title": "Realtek NIC"}], "other_count": 0})[0] == "available"
    # 0件でも、他に未適用更新が無ければ検索機構の生死は不明のまま
    assert driver_update_state({"drivers": [], "other_count": 0})[0] == "none_unproven"
    assert driver_update_state({"drivers": [], "other_count": 2})[0] == "none"
    # 抑止設定があっても、実際に更新が返っていればそちらを優先しない(抑止が先に立つ)
    assert driver_update_state({"wsus": "x", "drivers": [{"Title": "a"}]})[0] == "suppressed"

    # ドライバ日付: 読めない値で「古い」と決めつけない
    assert _driver_age_days(None) is None
    assert _driver_age_days("") is None
    assert _driver_age_days("not a date") is None
    assert _driver_age_days("/Date(1690000000000)/") > 300
    assert _driver_age_days("2020-01-01T00:00:00") > 2000
    assert _driver_age_days((datetime.now() + timedelta(days=30)).isoformat()) == 0  # 未来日は0に丸める

    # 各状態が analyze() で findings になること(重大度も含めて)
    for wu, expect_sev in (({"drivers": [{"Title": "X"}], "other_count": 1}, SEV_ADVISE),
                           ({"wsus": "http://w", "drivers": []}, SEV_ADVISE),
                           ({"error": "boom"}, SEV_INFO),
                           ({"drivers": [], "other_count": 3}, SEV_INFO)):
        got = [f for f in analyze(_base_data(wu=wu)) if f["cat"] == "ドライバ"]
        assert len(got) == 1, (wu, got)
        assert got[0]["sev"] == expect_sev, (wu, got[0])
    # wu が無い(採取していない)ときも「最新」とは言わせない
    no_wu = [f for f in analyze(_base_data()) if f["cat"] == "ドライバ"]
    assert len(no_wu) == 1 and "確認できなかった" in no_wu[0]["item"], no_wu

    print("tuning selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1200x720")
    root.title("Windows ネットワーク設定監査")
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
    tab = TuningTab(frame, ctx)
    if "--auto" in sys.argv:
        root.after(300, tab.start)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
