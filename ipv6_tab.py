#!/usr/bin/env python3
"""IPv6の詳細監査タブ。アドレス種別・経路MTU・ファイアウォール・到達性を個別に確認し、
「何が確認できて、何は確認できていないか」を分けて表示する。

■ この環境で実測して分かったこと (推測ではなく採取した出力に基づく)

1. `ping -6 -l <size>` では経路MTUは測れない。
   IPv6にはDFビットが無く(RFC 8200: 経路上のルータは断片化しない)、送信元が自分で
   フラグメントヘッダを付けて分割する。実測:
       ping -6 -n 1 -l 3000 2606:4700:4700::1111  -> 応答あり (rc=0)
   つまりサイズを上げても成功し続けるので、成功/失敗の二分探索が成立しない。
   IPv4版 nd.discover_path_mtu() が使う `-f` は明示的に拒否される:
       「オプション -f は IPv4 のみでサポートされています。」
   よって本モジュールの二分探索は ping ではなく **UDPソケット + IPV6_DONTFRAG**
   (IPPROTO_IPV6=41 / optname=14) を使う。これを立てるとカーネルが分割せず、
   経路MTUを超える送信は WSAEMSGSIZE (errno 10040) で即座にローカル失敗する。
   管理者権限は不要。実測: payload 1452 は成功、1453 は 10040。
       1452 + UDPヘッダ8 + IPv6ヘッダ40 = 1500

   なお1回目の送信は「まだPacket Too Bigを受け取っていない」段階では成功しうるため、
   1サイズにつき2回送って両方成功したときだけ「通った」と判定する(2回目は更新済みの
   経路MTUで弾かれる)。

2. ping -6 の出力にはIPv4にある「バイト数 =32」と「TTL=」が無い:
       2606:4700:4700::1111 からの応答: 時間 =19ms
   ただし `時間 =NNms` と統計行はIPv4と同形式なので nd.parse_ping_output() の
   正規表現 `=\\s*(\\d+)\\s*ms` がそのまま通る(末尾3件=最小/最大/平均)。再実装しない。

3. tracert -6 は宛先がIPv6リテラルで、nd.parse_tracert_output() のIPv4正規表現には
   一致しない。実測の生出力:
         1     3 ms     1 ms     1 ms  2400:2411:3b00:2800:1111:1111:1111:1111
         4     *        *        *     要求がタイムアウトしました。
         8    21 ms     *        *     2001:de8:c::1:3335:1
   `*` と ms が同じ行に混在する。アドレスは行末トークンを inet_pton で検証して拾う
   (「要求がタイムアウトしました。」は検証に落ちるので自然に除外される)。

4. エンコーディング: ping / tracert / powershell は cp932、netsh だけ UTF-8。
   `netsh interface ipv6 show privacy` を cp932 で読むと文字化けするため、
   プライバシー拡張の確認には powershell の Get-NetIPv6Protocol を使っている。

5. SuffixOrigin は EUI-64 の判定に使えない。この環境は RandomizeIdentifiers=Enabled の
   ため、安定SLAACアドレスが SuffixOrigin=Link (本来はMAC由来の意味) なのに
   インターフェイスIDはランダムだった。よってラベルではなく実バイト
   (インターフェイスIDの3・4バイト目が ff fe か) で判定する。
"""
import ipaddress
import json
import random
import socket
import struct
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import network_diag as nd

try:
    from settings_store import settings
except Exception:  # 単体起動でストアが無くても動くようにする
    settings = None

# ---------- 定数 ----------

IPV6_HEADER = 40
UDP_HEADER = 8
ICMPV6_HEADER = 8
IPV6_MIN_MTU = 1280          # RFC 8200 が保証する最小MTU
DONTFRAG_OVERHEAD = IPV6_HEADER + UDP_HEADER   # 48
PING6_OVERHEAD = IPV6_HEADER + ICMPV6_HEADER   # 48
WSAEMSGSIZE = 10040

IPPROTO_IPV6 = 41
IPV6_DONTFRAG = 14
PROBE_PORT = 33434           # traceroute慣例の未使用UDPポート

DEFAULT_V6_TARGET = "2606:4700:4700::1111"     # Cloudflare DNS
REACH_HOSTS = ["google.com", "cloudflare.com", "github.com", "www.softbank.jp"]
RTT_HOST = "google.com"      # A と AAAA の両方を持つ宛先で同条件比較する

_NET_GLOBAL = ipaddress.IPv6Network("2000::/3")
_NET_ULA = ipaddress.IPv6Network("fc00::/7")
_NET_LINKLOCAL = ipaddress.IPv6Network("fe80::/10")

ADDR_COLUMNS = [
    ("address", "IPv6アドレス", 300), ("kind", "種別", 110), ("iface", "インターフェイス", 130),
    ("origin", "取得方法", 110), ("suffix", "サフィックス", 130), ("state", "状態", 90),
    ("eui64", "EUI-64", 150), ("valid", "有効期限", 110), ("preferred", "優先期限", 110),
]
PATH_COLUMNS = [
    ("hop", "ホップ", 60), ("ip", "応答元", 340), ("rtt", "RTT(平均)", 90), ("note", "備考", 260),
]
FW_COLUMNS = [
    ("port", "ポート", 70), ("address", "バインド", 70), ("process", "プロセス", 130),
    ("pid", "PID", 60), ("rule", "一致した受信許可規則", 290), ("profile", "プロファイル", 100),
    ("remote", "許可元", 90), ("verdict", "判定", 270),
]
NET_COLUMNS = [
    ("item", "項目", 200), ("value", "値", 380), ("detail", "詳細", 420),
]


def _setting(dotted, fallback):
    try:
        value = settings.get(dotted) if settings else None
        return fallback if value is None else value
    except Exception:
        return fallback


def _aslist(data):
    """PowerShell 5.1 の ConvertTo-Json は要素1個の配列をオブジェクトに潰すので吸収する。"""
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def _ps_json(command, timeout=60):
    """PowerShellを実行してJSONを返す。空/失敗時は None(欠損)を返し、例外は投げない。"""
    try:
        out = nd.ps(command, timeout=timeout)
    except Exception as e:
        return None, str(e)
    if not out:
        return None, "出力なし"
    try:
        return json.loads(out), None
    except ValueError as e:
        return None, f"JSON解析失敗: {e}"


# ---------- アドレスの分類 (純粋関数) ----------

def is_eui64(address):
    """インターフェイスIDにMACが埋め込まれている(EUI-64由来)か。

    EUI-64 は MAC の中央に ff:fe を挿入して作るので、下位64ビットの
    3バイト目が 0xFF・4バイト目が 0xFE になる。SuffixOrigin ラベルは
    RandomizeIdentifiers が有効だと Link のままランダム値になるため信用しない。
    """
    try:
        packed = ipaddress.IPv6Address(address.split("%")[0]).packed
    except ValueError:
        return False
    return packed[11] == 0xFF and packed[12] == 0xFE


def eui64_mac(address):
    """EUI-64アドレスから埋め込まれたMACを復元する。EUI-64でなければ None。"""
    if not is_eui64(address):
        return None
    p = ipaddress.IPv6Address(address.split("%")[0]).packed
    octets = [p[8] ^ 0x02, p[9], p[10], p[13], p[14], p[15]]  # U/Lビットを戻す
    return ":".join(f"{o:02x}" for o in octets)


def address_kind(address):
    """グローバル / ULA / リンクローカル / ループバック / マルチキャスト / その他。"""
    a = address.split("%")[0]
    try:
        ip = ipaddress.IPv6Address(a)
    except ValueError:
        return "不正"
    if ip.is_loopback:
        return "ループバック"
    if ip in _NET_LINKLOCAL:
        return "リンクローカル"
    if ip in _NET_ULA:
        return "ULA"
    if ip.is_multicast:
        return "マルチキャスト"
    if ip in _NET_GLOBAL:
        return "グローバル"
    return "その他"


_ORIGIN_LABEL = {"RouterAdvertisement": "RA (SLAAC)", "Dhcp": "DHCPv6",
                 "Manual": "手動", "WellKnown": "予約", "Other": "その他"}
_SUFFIX_LABEL = {"Random": "一時アドレス", "Link": "リンク層(ラベル)",
                 "Manual": "手動", "WellKnown": "予約", "Dhcp": "DHCPv6", "Other": "その他"}


def classify_address(entry):
    """Get-NetIPAddress の1件を分類する。欠損キーは '-' として扱う。"""
    addr = (entry or {}).get("IPAddress") or ""
    base, _, zone = addr.partition("%")
    prefix_origin = (entry or {}).get("PrefixOrigin") or ""
    suffix_origin = (entry or {}).get("SuffixOrigin") or ""
    eui = is_eui64(base)
    return {
        "address": base,
        "zone": zone or None,
        "prefix_length": (entry or {}).get("PrefixLength"),
        "interface": (entry or {}).get("InterfaceAlias") or "-",
        "kind": address_kind(base),
        "origin": _ORIGIN_LABEL.get(prefix_origin, prefix_origin or "-"),
        "suffix": _SUFFIX_LABEL.get(suffix_origin, suffix_origin or "-"),
        "temporary": suffix_origin == "Random",
        "state": (entry or {}).get("AddressState") or "-",
        "eui64": eui,
        "eui64_mac": eui64_mac(base) if eui else None,
        "valid_lifetime": _short_lifetime((entry or {}).get("ValidLifetime")),
        "preferred_lifetime": _short_lifetime((entry or {}).get("PreferredLifetime")),
    }


def _short_lifetime(value):
    """TimeSpan文字列を短く。Windowsの「無期限」は 10675199.02:48:05.4775807 (TimeSpan.MaxValue)。"""
    if not value:
        return "-"
    s = str(value)
    if s.startswith("10675199"):
        return "無期限"
    return s.split(".")[0] if "." in s and s.count(":") >= 2 else s


# ---------- 経路MTU (二分探索) ----------

def search_mtu(probe, low, high):
    """probe(payload)->bool を満たす最大ペイロードを二分探索する。

    -> (最大ペイロード, 上限で通ったか) / 下限でも通らなければ (None, False)。
    IPv4版 nd.discover_path_mtu() と同じ探索だが、判定手段だけ差し替えている。
    """
    if low > high:
        return None, False
    if probe(high):
        return high, True
    if not probe(low):
        return None, False
    lo, hi = low, high
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if probe(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo, False


def dontfrag_probe(host, payload, port=PROBE_PORT, sends=2):
    """IPV6_DONTFRAG付きUDPを送る。経路MTU超過なら WSAEMSGSIZE でローカル失敗する。

    1回目は経路MTUがまだ縮んでいない段階なら成功しうる(送出後にPacket Too Bigが返る)。
    2回送って両方成功したときだけ True にすることで、更新後の経路MTUを見る。
    """
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.setsockopt(IPPROTO_IPV6, IPV6_DONTFRAG, 1)
        s.settimeout(2)
        for _ in range(sends):
            s.sendto(b"\0" * payload, (host, port))
            time.sleep(0.05)
        return True
    except OSError as e:
        if e.errno == WSAEMSGSIZE or getattr(e, "winerror", None) == WSAEMSGSIZE:
            return False
        raise
    finally:
        s.close()


def discover_ipv6_path_mtu(host, link_mtu=1500):
    """IPv6の経路MTUを実測する。ping -6 では測れないので DONTFRAG ソケットを使う。"""
    high = max(IPV6_MIN_MTU, min(int(link_mtu or 1500), 9000)) - DONTFRAG_OVERHEAD
    low = IPV6_MIN_MTU - DONTFRAG_OVERHEAD
    result = {"method": "UDP + IPV6_DONTFRAG の二分探索", "host": host,
              "link_mtu": link_mtu, "probe_low": low, "probe_high": high}
    try:
        payload, at_ceiling = search_mtu(lambda n: dontfrag_probe(host, n), low, high)
    except OSError as e:
        result["error"] = f"送信不可 (IPv6経路が無い可能性): {e}"
        return result
    if payload is None:
        result["error"] = (f"最小MTU {IPV6_MIN_MTU} 相当のペイロード {low} でも送信できない。"
                           "IPv6の送信自体が成立していない可能性がある")
        return result
    result["max_payload"] = payload
    result["mtu"] = payload + DONTFRAG_OVERHEAD
    result["at_link_ceiling"] = at_ceiling
    if at_ceiling:
        result["note"] = (f"リンクMTU {link_mtu} の上限まで分割されずに送れた。"
                          "経路上でPacket Too Bigを受け取っていないという意味であり、"
                          "リンクMTUより大きい経路MTUがあるかどうかはこの方法では測れない")
    else:
        result["note"] = ("リンクMTUより小さい値で頭打ちになった。"
                          "経路上のどこかがPacket Too Bigを返している")
    return result


# ---------- ping -6 / 宛先キャッシュ ----------

def ping6(host, count=4, size=None, timeout_ms=1500):
    """ping -6 を実行して nd.parse_ping_output() で解析する。生出力も返す。"""
    cmd = ["ping", "-6", "-n", str(count), "-w", str(timeout_ms)]
    if size is not None:
        cmd += ["-l", str(size)]
    cmd.append(host)
    try:
        r = nd.run(cmd, timeout=count * 3 + 15)  # cp932
    except Exception as e:
        return {"error": str(e), "raw": ""}
    parsed = nd.parse_ping_output(r.stdout)
    parsed["raw"] = r.stdout
    parsed["replied"] = parsed.get("loss_pct") is not None and parsed["loss_pct"] < 100
    if "見つかりません" in r.stdout:
        parsed["error"] = "名前解決に失敗"
    return parsed


def ping4(host, count=4, timeout_ms=1500):
    try:
        r = nd.run(["ping", "-4", "-n", str(count), "-w", str(timeout_ms), host],
                   timeout=count * 3 + 15)
    except Exception as e:
        return {"error": str(e)}
    parsed = nd.parse_ping_output(r.stdout)
    parsed["replied"] = parsed.get("loss_pct") is not None and parsed["loss_pct"] < 100
    return parsed


def parse_destination_cache(text):
    """netsh interface ipv6 show destinationcache (UTF-8) を解析する。

    行形式: `1500 2606:4700:4700::1111                          fe80::32f7:72ff:fec9:97a7`
    見出しは日本語/英語で変わるので、先頭が整数でアドレスが inet_pton を通る行だけ拾う。
    """
    entries = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        dest = parts[1]
        try:
            socket.inet_pton(socket.AF_INET6, dest.split("%")[0])
        except OSError:
            continue
        entries.append({"pmtu": int(parts[0]), "destination": dest,
                        "next_hop": parts[2] if len(parts) > 2 else None})
    return entries


def destination_cache():
    try:
        r = nd.run(["netsh", "interface", "ipv6", "show", "destinationcache"],
                   timeout=20, encoding="utf-8")  # netsh だけ UTF-8
        return parse_destination_cache(r.stdout), None
    except Exception as e:
        return [], str(e)


# ---------- tracert -6 ----------

def _is_ipv6(token):
    try:
        socket.inet_pton(socket.AF_INET6, token)
        return True
    except OSError:
        return False


def parse_tracert6(text, max_hops=30):
    """tracert -6 -d の出力を解析する。

    `*` と ms が同じ行に混在しうる (実測: `  8    21 ms     *        *     2001:de8:c::1:3335:1`)。
    アドレスは各トークンを inet_pton で検証して拾うので、
    「要求がタイムアウトしました。」のような日本語行は自然に落ちる。
    """
    hops = []
    for raw in text.splitlines():
        line = raw.strip()
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        hop_num = int(parts[0])
        if hop_num > max_hops:
            continue
        rest = parts[1:]
        times, ip = [], None
        for i, tok in enumerate(rest):
            if tok == "ms" and i > 0:
                prev = rest[i - 1].lstrip("<")
                if prev.isdigit():
                    times.append(int(prev))
            elif _is_ipv6(tok.split("%")[0]):
                ip = tok
        hops.append({
            "hop": hop_num,
            "ip": ip,
            "avg_ms": round(sum(times) / len(times), 1) if times else None,
            "probes_ok": len(times),
            "timeout": ip is None and not times,
        })
    return hops


def traceroute6(host, max_hops=15, wait_ms=800):
    try:
        r = nd.run(["tracert", "-6", "-d", "-h", str(max_hops), "-w", str(wait_ms), host],
                   timeout=max_hops * 4 + 20)
        return parse_tracert6(r.stdout, max_hops), r.stdout
    except Exception as e:
        return [], f"error: {e}"


# ---------- ファイアウォール / 待ち受けポート ----------

_FW_QUERY = (
    "$pf=@{}; Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | "
    "ForEach-Object { $pf[$_.InstanceID]=$_ }; "
    "$af=@{}; Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | "
    "ForEach-Object { $af[$_.InstanceID]=$_ }; "
    "$res=@(); $anyport=0; "
    "foreach($r in Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow "
    "-ErrorAction SilentlyContinue){ "
    "$f=$pf[$r.InstanceID]; if(-not $f){ continue } "
    "$proto=[string]$f.Protocol; if($proto -ne 'TCP' -and $proto -ne 'Any'){ continue } "
    "$lp=[string]($f.LocalPort -join ','); "
    "if($lp -eq 'Any'){ $anyport++; continue } "
    "$a=$af[$r.InstanceID]; "
    "$res += [pscustomobject]@{Name=[string]$r.DisplayName;Ports=$lp;Protocol=$proto;"
    "Profile=[string]$r.Profile;Remote=[string]($a.RemoteAddress -join ',')} } "
    "[pscustomobject]@{rules=@($res);any_port_rules=$anyport} | ConvertTo-Json -Compress -Depth 4"
)

_LISTEN_QUERY = (
    "$p=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $p[$_.Id]=$_.ProcessName }; "
    "@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LocalAddress -like '*:*' } | "
    "Select-Object LocalAddress,LocalPort,OwningProcess,"
    "@{n='Process';e={[string]$p[[int]$_.OwningProcess]}}) | ConvertTo-Json -Compress"
)


def parse_port_spec(spec):
    """'445' / '554,8554-8558' / 'RPC' / 'Any' を範囲リストにする。

    数値化できない指定 (RPC, IPHTTPSIn, Any) は None を返す = 突き合わせ対象外。
    """
    if not spec:
        return None
    ranges = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if not (lo.strip().isdigit() and hi.strip().isdigit()):
                return None
            ranges.append((int(lo), int(hi)))
        elif part.isdigit():
            ranges.append((int(part), int(part)))
        else:
            return None
    return ranges or None


def _profile_applies(rule_profile, active_profiles):
    """規則のプロファイル指定 ('Any' / 'Domain, Private') が現在のネットワーク種別に効くか。"""
    text = str(rule_profile or "")
    if "Any" in text:
        return True
    return any(p and p in text for p in active_profiles)


def match_listen_to_rules(listeners, rules, active_profiles):
    """`::` にバインドしている待ち受けポートに、有効な受信許可規則を突き合わせる。

    純粋関数。外部へのスキャンは一切行わない。規則が「有る」ことは
    「外部から届く」ことを意味しないので、判定は必ず条件付きで書く。
    """
    out = []
    for l in listeners:
        addr = (l or {}).get("LocalAddress") or ""
        if addr != "::":  # ::1 はループバック専用なので対象外
            continue
        port = (l or {}).get("LocalPort")
        matched = []
        for r in rules:
            ranges = parse_port_spec((r or {}).get("Ports"))
            if not ranges or port is None:
                continue
            if not any(lo <= port <= hi for lo, hi in ranges):
                continue
            applies = _profile_applies(r.get("Profile"), active_profiles)
            matched.append({"name": r.get("Name") or "-", "profile": r.get("Profile") or "-",
                            "remote": r.get("Remote") or "-", "active_profile": applies})
        active = [m for m in matched if m["active_profile"]]
        wide = [m for m in active if str(m["remote"]).strip() in ("Any", "*", "")]
        if wide:
            verdict, level = "現在のプロファイルで許可規則あり(許可元Any)", "warn"
        elif active:
            verdict, level = "許可規則あり(許可元は限定)", "info"
        elif matched:
            verdict, level = "許可規則はあるが別プロファイル向け", "info"
        else:
            verdict, level = "ポート指定の許可規則なし", "good"
        out.append({"port": port, "address": addr,
                    "process": (l or {}).get("Process") or "-",
                    "pid": (l or {}).get("OwningProcess"),
                    "matched": matched, "verdict": verdict, "level": level})
    out.sort(key=lambda r: (r["level"] != "warn", r["port"] if r["port"] is not None else 0))
    return out


# ---------- DNS ----------

def dns6_query(server, domain, qtype=28, timeout=2.0):
    """IPv6のDNSサーバへ直接AAAAを引いて応答時間を測る。

    nd.dns_query_time() は AF_INET 固定なのでIPv6サーバに使えない。最小限の複製。
    """
    qid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = b"".join(struct.pack("B", len(p)) + p.encode() for p in domain.split(".")) \
        + b"\x00" + struct.pack(">HH", qtype, 1)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        start = time.perf_counter()
        sock.sendto(header + question, (server, 53))
        data, _ = sock.recvfrom(1024)
        elapsed = (time.perf_counter() - start) * 1000
        if struct.unpack(">H", data[:2])[0] != qid:
            return None
        answers = struct.unpack(">H", data[6:8])[0]
        return {"server": server, "ms": round(elapsed, 1), "answers": answers}
    except Exception:
        return None
    finally:
        sock.close()


# ---------- 到達性 ----------

def reach_check(host, port=443, timeout=5.0):
    """AAAAの有無と、実際にIPv6でTCP接続できるかを分けて返す。"""
    entry = {"host": host, "aaaa": None, "connected": False, "connect_ms": None, "error": None}
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
    except socket.gaierror as e:
        entry["error"] = f"AAAAレコードなし / 名前解決不可 ({e.strerror or e})"
        return entry
    entry["aaaa"] = infos[0][4][0]
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        t0 = time.perf_counter()
        s.connect(infos[0][4])
        entry["connect_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        entry["connected"] = True
    except OSError as e:
        entry["error"] = f"AAAAはあるが接続不可: {e}"
    finally:
        s.close()
    return entry


# ---------- 所見の組み立て ----------

def build_findings(data):
    """各項目で「確認できたこと」と「確認できていないこと」を分けて返す。

    単純な断定 (IPv6有効=危険 / ファイアウォール有効=安全) を出さないため、
    両方のリストを必ず持たせる。
    """
    f = []

    # --- アドレス ---
    addrs = data.get("addresses", [])
    globals_ = [a for a in addrs if a["kind"] == "グローバル"]
    eui = [a for a in addrs if a["eui64"]]
    temps = [a for a in addrs if a["temporary"]]
    priv = data.get("privacy", {})
    ok, ng = [], []
    if globals_:
        ok.append(f"グローバルアドレス {len(globals_)} 件を保持 (端末が直接ルーティング対象)")
    else:
        ok.append("グローバルアドレスなし")
    ok.append(f"ULA {sum(1 for a in addrs if a['kind'] == 'ULA')} 件 / "
              f"リンクローカル {sum(1 for a in addrs if a['kind'] == 'リンクローカル')} 件 / "
              f"一時アドレス {len(temps)} 件")
    if priv.get("UseTemporaryAddresses"):
        ok.append(f"プライバシー拡張 UseTemporaryAddresses = {priv['UseTemporaryAddresses']}")
    if priv.get("RandomizeIdentifiers"):
        ok.append(f"インターフェイスID RandomizeIdentifiers = {priv['RandomizeIdentifiers']}")
    if eui:
        level = "bad"
        ok.append("EUI-64由来 (MAC埋め込み) のアドレスを検出: " +
                  ", ".join(f"{a['address']} -> MAC {a['eui64_mac']}" for a in eui))
        ng.append("このアドレスは端末を一意に追跡可能にする。プライバシー拡張が"
                  "効いていないインターフェイスがあるかは個別に確認が必要")
    else:
        level = "good" if temps else "info"
        ok.append("EUI-64由来 (ff:fe をインターフェイスID中央に持つ) のアドレスは検出されなかった"
                  " = MACはアドレスから読み取れない")
    ng.append("ここで見ているのはこの端末の設定だけ。同じLANの他の端末が"
              "EUI-64を使っているかは分からない")
    if not temps:
        ng.append("一時アドレスが1件も無い。送信元として使われるアドレスが固定である可能性")
    f.append({"title": "アドレスとプライバシー", "level": level, "ok": ok, "ng": ng})

    # --- 経路MTU ---
    mtu = data.get("path_mtu", {})
    frag = data.get("fragment_check", {})
    cache = data.get("destination_cache", {})
    ok, ng = [], []
    if mtu.get("mtu"):
        ok.append(f"IPv6の経路MTU 実測 {mtu['mtu']} バイト "
                  f"(分割されず送れた最大UDPペイロード {mtu['max_payload']} + ヘッダ48)")
        ok.append(f"手法: {mtu['method']} / 宛先 {mtu.get('host')}")
        if mtu.get("note"):
            ok.append(mtu["note"])
        level = "good" if mtu["mtu"] >= 1500 else "warn"
    else:
        ok.append(f"経路MTUを測れなかった: {mtu.get('error', '不明')}")
        level = "bad"
    if frag.get("small") is not None:
        ok.append(f"ping -6 -l {frag['small_size']} (分割不要): "
                  f"{'応答あり' if frag['small'] else '応答なし'}")
    if frag.get("large") is not None:
        ok.append(f"ping -6 -l {frag['large_size']} (送信元で分割される): "
                  f"{'応答あり = フラグメントの送受信と再組立ては通る' if frag['large'] else '応答なし = IPv6フラグメントが途中で落とされている疑い'}")
    if cache.get("min_pmtu") is not None:
        ok.append(f"Windowsの宛先キャッシュ: {cache['entries']} 件、"
                  f"最小PMTU {cache['min_pmtu']} / リンクMTU {mtu.get('link_mtu')}")
    ng.append("ping -6 にDFビットは無く、送信元が自分で分割するためサイズを上げても成功し続ける。"
              "ping -6 の成功/失敗だけでは経路MTUは測れない (この実測での確認事項)")
    if cache.get("has_reduced") is False:
        ng.append("経路上に1500未満の区間が見つからないため、ICMPv6 Packet Too Big が"
                  "正しく返ってくるかは検証できていない (縮んだPMTUの実例が無い)")
    ng.append("測った宛先1つの経路についての値。別の宛先や別の時刻に同じとは限らない")
    f.append({"title": "経路MTUとPMTUD", "level": level, "ok": ok, "ng": ng})

    # --- ファイアウォール ---
    fw = data.get("firewall", {})
    exposure = data.get("exposure", [])
    ok, ng = [], []
    profiles = fw.get("profiles", [])
    if profiles:
        ok.append("プロファイル: " + " / ".join(
            f"{p.get('Name')}={'有効' if str(p.get('Enabled')) == 'True' else '無効'}"
            f"(受信既定 {p.get('DefaultInboundAction')})" for p in profiles))
    else:
        ok.append("プロファイル情報を取得できなかった")
    if fw.get("active_profiles"):
        ok.append("現在接続中のネットワーク種別: " + ", ".join(fw["active_profiles"]))
    listen_all = [e for e in exposure]
    warn_rows = [e for e in exposure if e["level"] == "warn"]
    ok.append(f"`::` にバインドしている待ち受けTCPポート {len(listen_all)} 件: " +
              (", ".join(str(e["port"]) for e in listen_all) or "なし"))
    if warn_rows:
        for e in warn_rows:
            names = ", ".join(m["name"] for m in e["matched"] if m["active_profile"])
            ok.append(f"ポート {e['port']} ({e['process']}) は現在のプロファイルで"
                      f"許可元Anyの受信許可規則に一致: {names}")
    disabled = [p for p in profiles if str(p.get("Enabled")) != "True"]
    if disabled:
        level = "bad"
        ng.append("無効なプロファイルがある。IPv6はNATが無く各端末が直接ルーティング対象なので、"
                  "無効時は上記の待ち受けポートがそのまま外部に晒される")
    elif warn_rows:
        level = "warn"
    else:
        level = "good"
    ng.append("外部からのスキャンは一切行っていない。規則が存在することと"
              "実際に外部から届くことは別 (上流ルータ側のフィルタ、ISP側の遮断で届かない場合がある)")
    ng.append(f"ポート指定ではなくプログラム指定の受信許可規則が {fw.get('any_port_rules', '?')} 件あり、"
              "これらは本突き合わせの対象外。該当プログラムが待ち受けていれば規則なしに見えても通る")
    ng.append("外部からの到達性を確かめたい場合は、自分で ipv6-test.com などの外部サービスを"
              "開いてポートスキャンを依頼するか、別回線の端末から接続を試すこと。"
              "この診断は明示的な操作なしに外部サービスへ依頼しない")
    f.append({"title": "ファイアウォールと露出", "level": level, "ok": ok, "ng": ng})

    # --- DNS / 到達性 / RTT ---
    dns = data.get("dns", {})
    reach = data.get("reachability", [])
    rtt = data.get("rtt", {})
    ok, ng = [], []
    servers = dns.get("servers", [])
    if servers:
        ok.append("配られているIPv6 DNSサーバ: " + ", ".join(servers))
    else:
        ok.append("IPv6のDNSサーバは配られていない (IPv4のDNSに依存)")
    if dns.get("probe"):
        p = dns["probe"]
        ok.append(f"{p['server']} へAAAAを直接問い合わせ: {p['ms']}ms / 回答 {p['answers']} 件")
    elif servers:
        ok.append("IPv6 DNSサーバへの直接問い合わせは応答が得られなかった")
    have = [r for r in reach if r["aaaa"]]
    conn = [r for r in reach if r["connected"]]
    ok.append(f"主要サイトのIPv6到達性: AAAAあり {len(have)}/{len(reach)}、"
              f"実際に接続できた {len(conn)}/{len(reach)}")
    for r in reach:
        ok.append(f"  {r['host']}: " + (f"{r['aaaa']} 接続 {r['connect_ms']}ms"
                                        if r["connected"] else (r["error"] or "不明")))
    if rtt.get("v4_ms") is not None and rtt.get("v6_ms") is not None:
        diff = rtt["v6_ms"] - rtt["v4_ms"]
        ok.append(f"RTT比較 ({rtt['host']}): IPv4 {rtt['v4_ms']}ms / IPv6 {rtt['v6_ms']}ms "
                  f"(差 {diff:+.0f}ms)")
        ng.append("同じホスト名でもIPv4とIPv6で別のサーバに繋がることがあるため、"
                  "RTT差がそのまま回線の差とは限らない")
    level = "good" if conn else ("warn" if have else "bad")
    missing = [r["host"] for r in reach if not r["aaaa"]]
    if missing:
        ng.append("AAAAが無いサイト (" + ", ".join(missing) + ") は相手側の都合であり、"
                  "こちらのIPv6の問題ではない")
    ng.append("到達性は測定時点の数件のサンプル。IPv6経路全体の健全性を示すものではない")
    f.append({"title": "DNS・到達性・RTT", "level": level, "ok": ok, "ng": ng})
    return f


# ---------- 監査本体 ----------

def run_audit(target, progress=lambda msg: None):
    """IPv6の詳細監査を通しで実行する。ワーカースレッドから呼ぶこと。"""
    data = {"timestamp": datetime.now().isoformat(timespec="seconds"), "target": target}

    progress("アドレスを取得中…")
    raw, err = _ps_json(
        "Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress,InterfaceIndex,InterfaceAlias,PrefixLength,"
        "@{n='PrefixOrigin';e={[string]$_.PrefixOrigin}},"
        "@{n='SuffixOrigin';e={[string]$_.SuffixOrigin}},"
        "@{n='AddressState';e={[string]$_.AddressState}},"
        "@{n='ValidLifetime';e={[string]$_.ValidLifetime}},"
        "@{n='PreferredLifetime';e={[string]$_.PreferredLifetime}} | ConvertTo-Json -Compress")
    data["addresses"] = [classify_address(e) for e in _aslist(raw)]
    if err:
        data["addresses_error"] = err

    progress("インターフェイスと経路を取得中…")
    raw, _ = _ps_json(
        "Get-NetIPInterface -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceIndex,InterfaceAlias,NlMtu,"
        "@{n='ConnectionState';e={[string]$_.ConnectionState}},"
        "@{n='Dhcp';e={[string]$_.Dhcp}},"
        "@{n='RouterDiscovery';e={[string]$_.RouterDiscovery}},"
        "InterfaceMetric | ConvertTo-Json -Compress")
    data["interfaces"] = _aslist(raw)
    raw, _ = _ps_json(
        "Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | "
        "Select-Object NextHop,InterfaceAlias,InterfaceIndex,RouteMetric | ConvertTo-Json -Compress")
    data["default_routes"] = _aslist(raw)
    raw, _ = _ps_json(
        "Get-NetIPv6Protocol | Select-Object "
        "@{n='UseTemporaryAddresses';e={[string]$_.UseTemporaryAddresses}},"
        "@{n='RandomizeIdentifiers';e={[string]$_.RandomizeIdentifiers}} | ConvertTo-Json -Compress")
    data["privacy"] = (_aslist(raw) or [{}])[0]

    # 既定経路を持つインターフェイスのMTUを使う (ループバックの 4294967295 を拾わないため)
    route_ifs = {r.get("InterfaceIndex") for r in data["default_routes"]}
    link_mtu = next((i.get("NlMtu") for i in data["interfaces"]
                     if i.get("InterfaceIndex") in route_ifs and i.get("NlMtu")), 1500)
    data["link_mtu"] = link_mtu

    progress("経路MTUを二分探索中…")
    data["path_mtu"] = discover_ipv6_path_mtu(target, link_mtu)

    progress("ICMPv6とフラグメントを確認中…")
    small = max(0, min(int(link_mtu or 1500), 1500) - PING6_OVERHEAD)
    large = min(int(link_mtu or 1500), 1500) + 500      # 必ず送信元で分割される大きさ
    ps_small, ps_large = ping6(target, count=1, size=small), ping6(target, count=1, size=large)
    data["fragment_check"] = {"small_size": small, "small": ps_small.get("replied"),
                              "large_size": large, "large": ps_large.get("replied"),
                              "raw_small": ps_small.get("raw", ""), "raw_large": ps_large.get("raw", "")}
    entries, cache_err = destination_cache()
    reduced = [e for e in entries if 1280 <= e["pmtu"] < (link_mtu or 1500)]
    data["destination_cache"] = {
        "entries": len(entries), "error": cache_err,
        "min_pmtu": min((e["pmtu"] for e in entries if e["pmtu"] <= 65535), default=None),
        "has_reduced": bool(reduced) if entries else None,
        "reduced": reduced[:10],
    }

    progress("tracert -6 を実行中…")
    hops, raw_tr = traceroute6(target)
    data["traceroute"] = hops
    data["traceroute_raw"] = raw_tr

    progress("ファイアウォールと待ち受けポートを突き合わせ中…")
    fw_raw, fw_err = _ps_json(_FW_QUERY, timeout=120)
    rules = _aslist((fw_raw or {}).get("rules"))
    prof_raw, _ = _ps_json(
        "Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,"
        "@{n='Enabled';e={[string]$_.Enabled}},"
        "@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}},"
        "@{n='DefaultOutboundAction';e={[string]$_.DefaultOutboundAction}} | ConvertTo-Json -Compress")
    conn_raw, _ = _ps_json(
        "Get-NetConnectionProfile | Select-Object InterfaceAlias,"
        "@{n='NetworkCategory';e={[string]$_.NetworkCategory}} | ConvertTo-Json -Compress")
    active = sorted({c.get("NetworkCategory") for c in _aslist(conn_raw) if c.get("NetworkCategory")})
    data["firewall"] = {"profiles": _aslist(prof_raw), "active_profiles": active,
                        "rules": rules, "any_port_rules": (fw_raw or {}).get("any_port_rules"),
                        "error": fw_err}
    listen_raw, _ = _ps_json(_LISTEN_QUERY, timeout=60)
    data["listeners"] = _aslist(listen_raw)
    data["exposure"] = match_listen_to_rules(data["listeners"], rules, active)

    progress("DNSを確認中…")
    dns_raw, _ = _ps_json(
        "Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses | ConvertTo-Json -Compress")
    servers = []
    for e in _aslist(dns_raw):
        if e.get("InterfaceIndex") in route_ifs:
            servers += [s for s in _aslist(e.get("ServerAddresses")) if s]
    data["dns"] = {"servers": servers,
                   "probe": dns6_query(servers[0], "example.com") if servers else None}

    progress("主要サイトへの到達性を確認中…")
    data["reachability"] = [reach_check(h) for h in REACH_HOSTS]

    progress("IPv4とIPv6のRTTを比較中…")
    v4, v6 = ping4(RTT_HOST, count=5), ping6(RTT_HOST, count=5)
    data["rtt"] = {"host": RTT_HOST, "v4_ms": v4.get("avg_ms"), "v6_ms": v6.get("avg_ms"),
                   "v4_loss_pct": v4.get("loss_pct"), "v6_loss_pct": v6.get("loss_pct"),
                   "ipv4_target": _setting("targets.primary", "1.1.1.1")}

    data["findings"] = build_findings(data)
    return data


def save_audit(data):
    nd.RESULTS_DIR.mkdir(exist_ok=True)
    path = nd.RESULTS_DIR / f"ipv6_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


# ---------- タブ ----------

class IPv6Tab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.data = None
        self._stop = threading.Event()
        self._thread = None

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        ttk.Label(top, text="IPv6ターゲット").grid(row=0, column=0, padx=(0, 6))
        self.target_var = tk.StringVar(value=_setting("targets.ipv6_primary", DEFAULT_V6_TARGET))
        ttk.Entry(top, textvariable=self.target_var, width=34).grid(row=0, column=1, padx=(0, 12))
        self.run_btn = ttk.Button(top, text="▶  監査を実行", style="Accent.TButton", command=self.start)
        self.run_btn.grid(row=0, column=2, padx=4)

        self.status = ttk.Label(parent, text="未実行", padding=(6, 4))
        self.status.pack(fill="x")

        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True, padx=4, pady=(4, 8))

        # 所見
        fr = ttk.Frame(self.nb)
        self.nb.add(fr, text="所見")
        self.text = tk.Text(fr, wrap="word", height=20, borderwidth=0, padx=10, pady=8)
        sb = ttk.Scrollbar(fr, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        self.trees = {}
        for key, label, cols in (("addr", "アドレス", ADDR_COLUMNS),
                                 ("path", "経路 / MTU", PATH_COLUMNS),
                                 ("fw", "ファイアウォール / 待ち受け", FW_COLUMNS),
                                 ("net", "DNS / 到達性", NET_COLUMNS)):
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=label)
            tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", height=18)
            for ckey, head, width in cols:
                tree.heading(ckey, text=head)
                tree.column(ckey, width=width, anchor="w",
                            stretch=ckey in ("rule", "detail", "note", "verdict"))
            vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            tree.pack(side="left", fill="both", expand=True)
            self.trees[key] = tree

        self.on_theme_changed()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        self.text.configure(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"],
                            font=(self.ctx.font, 10))
        for tag, color in (("good", t["good"]), ("warn", t["warn"]), ("bad", t["bad"]),
                           ("muted", t["muted"]), ("info", t["fg"])):
            self.text.tag_configure(tag, foreground=color)
        self.text.tag_configure("head", foreground=t["fg"], font=(self.ctx.font, 11, "bold"))
        for tree in self.trees.values():
            for tag in ("good", "warn", "bad", "muted"):
                tree.tag_configure(tag, foreground=t[tag])
        # sv_ttk が style map に -foreground を仕込んでおり、そのままだと行タグ色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる (pathmon_tab.py と同じ対処)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.status.config(foreground=t["muted"])

    # ---- 制御 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.run_btn.config(state="disabled")
        self._set_status("監査を開始しました…", "muted")
        self._thread = threading.Thread(target=self._worker, args=(self.target_var.get().strip(),),
                                        daemon=True)
        self._thread.start()

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _post(self, fn, *args):
        """UI更新はメインスレッドへ。mainloop終了後の after は RuntimeError になるので握る。"""
        try:
            self.ctx.root.after(0, lambda: fn(*args))
        except (RuntimeError, tk.TclError):
            pass

    def _worker(self, target):
        try:
            data = run_audit(target or DEFAULT_V6_TARGET,
                             progress=lambda m: self._post(self._set_status, m, "muted"))
            if self._stop.is_set():
                return
            path = save_audit(data)
            self._post(self._render, data, path)
        except Exception as e:
            self._post(self._set_status, f"監査に失敗: {e}", "bad")
        finally:
            self._post(lambda: self.run_btn.config(state="normal"))

    def _set_status(self, msg, level="muted"):
        try:
            self.status.config(text=msg, foreground=self.ctx.theme[level])
        except tk.TclError:
            pass

    # ---- 表示 ----

    def _render(self, data, path):
        self.data = data
        self._render_findings(data)
        self._render_addresses(data)
        self._render_path(data)
        self._render_firewall(data)
        self._render_net(data)
        self._set_status(f"✓ 完了 ({data['timestamp']})  保存: {path.name}", "good")

    def _render_findings(self, data):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        mark = {"good": "OK", "warn": "注意", "bad": "要確認", "info": "情報"}
        for item in data.get("findings", []):
            lvl = item["level"]
            self.text.insert("end", f"[{mark.get(lvl, lvl)}] {item['title']}\n", ("head", lvl))
            self.text.insert("end", "  確認できたこと\n", "head")
            for line in item["ok"]:
                self.text.insert("end", f"    ・{line}\n", lvl if lvl != "info" else "info")
            self.text.insert("end", "  確認できていないこと / 断定できないこと\n", "head")
            for line in item["ng"]:
                self.text.insert("end", f"    ・{line}\n", "muted")
            self.text.insert("end", "\n")
        self.text.config(state="disabled")

    def _render_addresses(self, data):
        tree = self.trees["addr"]
        tree.delete(*tree.get_children())
        for a in data.get("addresses", []):
            if a["eui64"]:
                tag, eui = "bad", f"⚠ MAC {a['eui64_mac']}"
            elif a["temporary"]:
                tag, eui = "good", "いいえ (一時アドレス)"
            elif a["kind"] in ("グローバル", "ULA", "リンクローカル"):
                tag, eui = "muted", "いいえ (ランダムID)"
            else:
                tag, eui = "muted", "-"
            prefix = f"/{a['prefix_length']}" if a["prefix_length"] is not None else ""
            tree.insert("", "end", values=(a["address"] + prefix, a["kind"], a["interface"],
                                           a["origin"], a["suffix"], a["state"], eui,
                                           a["valid_lifetime"], a["preferred_lifetime"]),
                        tags=(tag,))

    def _render_path(self, data):
        tree = self.trees["path"]
        tree.delete(*tree.get_children())
        mtu = data.get("path_mtu", {})
        tree.insert("", "end", values=("MTU", f"リンクMTU {data.get('link_mtu')}",
                                       "-", "Get-NetIPInterface の NlMtu"), tags=("muted",))
        if mtu.get("mtu"):
            tree.insert("", "end", values=("MTU", f"経路MTU 実測 {mtu['mtu']}",
                                           "-", mtu.get("note", "")),
                        tags=("good" if mtu["mtu"] >= 1500 else "warn",))
        else:
            tree.insert("", "end", values=("MTU", "測定不能", "-", mtu.get("error", "")),
                        tags=("bad",))
        frag = data.get("fragment_check", {})
        for key, label in (("small", "分割不要"), ("large", "分割あり")):
            v = frag.get(key)
            tree.insert("", "end", values=("ping-6", f"-l {frag.get(key + '_size')} ({label})",
                                           "-", "応答あり" if v else "応答なし"),
                        tags=("good" if v else "warn",))
        for h in data.get("traceroute", []):
            tag = "muted" if h["ip"] else "warn"
            note = "無応答" if h["timeout"] else (f"応答 {h['probes_ok']}/3" if h["ip"] else "")
            tree.insert("", "end", values=(h["hop"], h["ip"] or "*",
                                           h["avg_ms"] if h["avg_ms"] is not None else "-", note),
                        tags=(tag,))

    def _render_firewall(self, data):
        tree = self.trees["fw"]
        tree.delete(*tree.get_children())
        for p in data.get("firewall", {}).get("profiles", []):
            enabled = str(p.get("Enabled")) == "True"
            tree.insert("", "end", values=("-", "-", "ファイアウォール", "-",
                                           f"プロファイル {p.get('Name')}",
                                           "有効" if enabled else "無効", "-",
                                           f"受信の既定動作 {p.get('DefaultInboundAction', '-')}"),
                        tags=("good" if enabled else "bad",))
        for e in data.get("exposure", []):
            names = "; ".join(m["name"] for m in e["matched"]) or "-"
            profs = "; ".join(m["profile"] for m in e["matched"]) or "-"
            remotes = "; ".join(m["remote"] for m in e["matched"]) or "-"
            tree.insert("", "end", values=(e["port"], e["address"], e["process"], e["pid"],
                                           names, profs, remotes, e["verdict"]),
                        tags=(e["level"] if e["level"] != "info" else "muted",))

    def _render_net(self, data):
        tree = self.trees["net"]
        tree.delete(*tree.get_children())
        dns = data.get("dns", {})
        tree.insert("", "end", values=("IPv6 DNSサーバ", ", ".join(dns.get("servers") or []) or "なし",
                                       "Get-DnsClientServerAddress -AddressFamily IPv6"),
                    tags=("good" if dns.get("servers") else "warn",))
        probe = dns.get("probe")
        tree.insert("", "end", values=("IPv6 DNS 実測",
                                       f"{probe['ms']}ms / 回答 {probe['answers']} 件" if probe else "応答なし",
                                       "example.com の AAAA をIPv6で直接問い合わせ"),
                    tags=("good" if probe else "warn",))
        for r in data.get("reachability", []):
            if r["connected"]:
                tag, val, detail = "good", r["aaaa"], f"TCP 443 接続 {r['connect_ms']}ms"
            elif r["aaaa"]:
                tag, val, detail = "warn", r["aaaa"], r["error"] or "接続できず"
            else:
                tag, val, detail = "muted", "AAAAなし", r["error"] or "-"
            tree.insert("", "end", values=(r["host"], val, detail), tags=(tag,))
        rtt = data.get("rtt", {})
        if rtt:
            tree.insert("", "end", values=(f"RTT {rtt.get('host')}",
                                           f"IPv4 {rtt.get('v4_ms')}ms / IPv6 {rtt.get('v6_ms')}ms",
                                           "同じホスト名でも別サーバに繋がることがある点に注意"),
                        tags=("muted",))
        for r in data.get("default_routes", []):
            tree.insert("", "end", values=("既定経路 ::/0", r.get("NextHop", "-"),
                                           f"{r.get('InterfaceAlias', '-')} / metric {r.get('RouteMetric', '-')}"),
                        tags=("good",))


# ---------- 自己テスト ----------

# 実機で採取した本物の出力 (推測ではない)
REAL_PING6 = """
2606:4700:4700::1111 に ping を送信しています 32 バイトのデータ:
2606:4700:4700::1111 からの応答: 時間 =19ms

2606:4700:4700::1111 の ping 統計:
    パケット数: 送信 = 1、受信 = 1、損失 = 0 (0% の損失)、
ラウンド トリップの概算時間 (ミリ秒):
    最小 = 19ms、最大 = 19ms、平均 = 19ms
"""

REAL_PING6_LOSS = """
2001:db8::1 に ping を送信しています 32 バイトのデータ:
要求がタイムアウトしました。

2001:db8::1 の ping 統計:
    パケット数: 送信 = 1、受信 = 0、損失 = 1 (100% の損失)、
"""

REAL_TRACERT6 = """
2606:4700:4700::1111 へのルートをトレースしています。経由するホップ数は最大 10 です

  1     3 ms     1 ms     1 ms  2400:2411:3b00:2800:1111:1111:1111:1111
  2     3 ms     2 ms     6 ms  2400:2411:3b00:2800:2eff:65ff:fed8:e601
  3     6 ms     6 ms     6 ms  2400:2411:3b00:2900::fffe
  4     *        *        *     要求がタイムアウトしました。
  5     *        *        *     要求がタイムアウトしました。
  6     6 ms     7 ms     5 ms  2400:2000:bb1a:181a::1
  7     7 ms    15 ms    11 ms  2400:2000:2:0:1a::39
  8    21 ms     *        *     2001:de8:c::1:3335:1
  9     9 ms     6 ms     7 ms  2400:cb00:408:3::
 10     7 ms    12 ms     8 ms  2606:4700:4700::1111

トレースを完了しました。
"""

REAL_DESTCACHE = """
インターフェイス 1: Loopback Pseudo-Interface 1


PMTU 宛先アドレス                                  次ホップ アドレス
---- --------------------------------------------- -------------------------
65535 ::1                                           ::1

インターフェイス 2: イーサネット


PMTU 宛先アドレス                                  次ホップ アドレス
---- --------------------------------------------- -------------------------
1500 2606:4700:4700::1111                          fe80::32f7:72ff:fec9:97a7
1280 2001:db8:dead::1                              fe80::32f7:72ff:fec9:97a7
65535 2400:2411:3b00:2800:1d25:7efd:cdef:3883       2400:2411:3b00:2800:1d25:7efd:cdef:3883
"""


def _selftest():
    # --- EUI-64 判定の境界 ---
    # 実機の自アドレス: RandomizeIdentifiers 有効なのでランダム = EUI-64ではない
    assert not is_eui64("2400:2411:3b00:2800:1d25:7efd:cdef:3883")
    assert not is_eui64("fe80::c247:398d:bf00:c20d%2")          # ゾーンID付きでも落ちない
    # 実機の上流ルータ: これは EUI-64 (2eff:65ff:fed8:e601)
    assert is_eui64("2400:2411:3b00:2800:2eff:65ff:fed8:e601")
    assert eui64_mac("2400:2411:3b00:2800:2eff:65ff:fed8:e601") == "2c:ff:65:d8:e6:01"
    # 教科書例: MAC 00:11:22:33:44:55 -> 0211:22ff:fe33:4455
    assert is_eui64("2001:db8::211:22ff:fe33:4455")
    assert eui64_mac("2001:db8::211:22ff:fe33:4455") == "00:11:22:33:44:55"
    # 境界: ff/fe が入れ替わっている / 位置が1つずれている場合は EUI-64 ではない
    assert not is_eui64("2001:db8::211:22fe:ff33:4455")
    assert not is_eui64("2001:db8::211:2fff:e334:4455")
    # 境界: インターフェイスIDがほぼゼロでも ff:fe の位置さえ合えば EUI-64
    assert is_eui64("2001:db8::ff:fe00:0")
    assert not is_eui64("2001:db8::")
    assert not is_eui64("not-an-address")                        # 不正入力で例外を出さない
    assert eui64_mac("2001:db8::") is None

    # --- 種別の分類 ---
    assert address_kind("2400:2411:3b00:2800::1") == "グローバル"
    assert address_kind("2000::1") == "グローバル"               # 2000::/3 の下端
    assert address_kind("3fff::1") == "グローバル"               # 2000::/3 の上端
    assert address_kind("4000::1") == "その他"                   # 範囲外
    assert address_kind("fc00::1") == "ULA" and address_kind("fdff::1") == "ULA"
    assert address_kind("fe80::1") == "リンクローカル"
    assert address_kind("febf::1") == "リンクローカル"           # fe80::/10 の上端
    assert address_kind("fec0::1") == "その他"                   # 旧サイトローカルは範囲外
    assert address_kind("::1") == "ループバック"
    assert address_kind("ff02::1") == "マルチキャスト"
    assert address_kind("zzz") == "不正"

    # --- 実機のGet-NetIPAddress 1件をそのまま分類 ---
    temp = classify_address({
        "IPAddress": "2400:2411:3b00:2800:89cd:3e3b:bb9d:6df3", "InterfaceAlias": "イーサネット",
        "PrefixLength": 128, "PrefixOrigin": "RouterAdvertisement", "SuffixOrigin": "Random",
        "AddressState": "Preferred", "ValidLifetime": "23:56:00", "PreferredLifetime": "02:00:52"})
    assert temp["kind"] == "グローバル" and temp["temporary"] and not temp["eui64"]
    assert temp["origin"] == "RA (SLAAC)" and temp["suffix"] == "一時アドレス"
    assert temp["valid_lifetime"] == "23:56:00"

    ll = classify_address({
        "IPAddress": "fe80::c247:398d:bf00:c20d%2", "InterfaceAlias": "イーサネット",
        "PrefixLength": 64, "PrefixOrigin": "WellKnown", "SuffixOrigin": "Link",
        "AddressState": "Preferred", "ValidLifetime": "10675199.02:48:05.4775807",
        "PreferredLifetime": "10675199.02:48:05.4775807"})
    assert ll["kind"] == "リンクローカル" and ll["zone"] == "2" and ll["address"] == "fe80::c247:398d:bf00:c20d"
    assert ll["valid_lifetime"] == "無期限"
    # SuffixOrigin=Link でも EUI-64 とは限らない (RandomizeIdentifiers 有効時)。ラベルを信用しない
    assert ll["suffix"] == "リンク層(ラベル)" and ll["eui64"] is False

    # --- 欠損データ ---
    empty = classify_address({})
    assert empty["address"] == "" and empty["kind"] == "不正" and empty["eui64"] is False
    assert empty["origin"] == "-" and empty["valid_lifetime"] == "-" and empty["interface"] == "-"
    assert classify_address(None)["kind"] == "不正"
    assert _aslist(None) == [] and _aslist({"a": 1}) == [{"a": 1}] and _aslist([1, 2]) == [1, 2]

    # --- MTU 二分探索 ---
    calls = []

    def fake(limit):
        def probe(n):
            calls.append(n)
            return n <= limit
        return probe

    assert search_mtu(fake(1452), 1232, 1452) == (1452, True)      # 上限で通過
    calls.clear()
    assert search_mtu(fake(1400), 1232, 1452) == (1400, False)     # 途中で頭打ち
    assert max(calls) <= 1452 and min(calls) >= 1232               # 範囲外を叩かない
    assert len(calls) <= 12                                        # 線形探索になっていない
    assert search_mtu(fake(1231), 1232, 1452) == (None, False)     # 下限でも通らない
    assert search_mtu(fake(1232), 1232, 1452) == (1232, False)     # 下限ちょうど
    assert search_mtu(fake(1451), 1232, 1452) == (1451, False)     # 上限-1
    assert search_mtu(fake(1500), 1452, 1232) == (None, False)     # 範囲が逆転していても落ちない
    # 実機の実測値との整合: ペイロード1452が通り1453が通らない -> MTU 1500
    assert search_mtu(fake(1452), 1232, 1452)[0] + DONTFRAG_OVERHEAD == 1500
    assert IPV6_MIN_MTU - DONTFRAG_OVERHEAD == 1232

    # --- ping -6 の解析 (実機出力) ---
    p = nd.parse_ping_output(REAL_PING6)
    assert p["loss_pct"] == 0 and (p["min_ms"], p["max_ms"], p["avg_ms"]) == (19, 19, 19), p
    lost = nd.parse_ping_output(REAL_PING6_LOSS)
    assert lost["loss_pct"] == 100 and lost["avg_ms"] is None, lost
    assert nd.parse_ping_output("")["loss_pct"] is None

    # --- tracert -6 の解析 (実機出力) ---
    hops = parse_tracert6(REAL_TRACERT6)
    assert len(hops) == 10, hops
    assert hops[0]["ip"] == "2400:2411:3b00:2800:1111:1111:1111:1111" and hops[0]["avg_ms"] == 1.7
    assert hops[3]["ip"] is None and hops[3]["timeout"] and hops[3]["avg_ms"] is None
    # ms と * が混在する行: アドレスは拾い、届いた1発だけで平均を出す
    assert hops[7]["ip"] == "2001:de8:c::1:3335:1" and hops[7]["probes_ok"] == 1
    assert hops[7]["avg_ms"] == 21.0 and not hops[7]["timeout"]
    # `::` で終わるアドレスも落とさない
    assert hops[8]["ip"] == "2400:cb00:408:3::"
    assert hops[9]["ip"] == "2606:4700:4700::1111"
    assert parse_tracert6(REAL_TRACERT6, max_hops=3) == hops[:3]
    assert parse_tracert6("") == [] and parse_tracert6("トレースを完了しました。") == []
    # IPv4のtracertを食わせてもIPv6アドレスとしては拾わない
    assert parse_tracert6("  1     1 ms     1 ms     1 ms  192.168.3.1")[0]["ip"] is None

    # --- 宛先キャッシュの解析 (実機出力) ---
    cache = parse_destination_cache(REAL_DESTCACHE)
    assert len(cache) == 4, cache            # 見出し行と区切り線は落ちる
    assert cache[0] == {"pmtu": 65535, "destination": "::1", "next_hop": "::1"}
    assert {"pmtu": 1500, "destination": "2606:4700:4700::1111",
            "next_hop": "fe80::32f7:72ff:fec9:97a7"} in cache
    assert any(c["pmtu"] == 1280 for c in cache)
    assert parse_destination_cache("") == []

    # --- ポート指定の解析 ---
    assert parse_port_spec("445") == [(445, 445)]
    assert parse_port_spec("554,8554-8558") == [(554, 554), (8554, 8558)]
    assert parse_port_spec("RPC") is None and parse_port_spec("Any") is None
    assert parse_port_spec("IPHTTPSIn") is None and parse_port_spec("") is None
    assert parse_port_spec(None) is None and parse_port_spec("80-") is None

    # --- 待ち受けポートと規則の突き合わせ (実機データ) ---
    listeners = [
        {"LocalAddress": "::", "LocalPort": 445, "OwningProcess": 4, "Process": "System"},
        {"LocalAddress": "::", "LocalPort": 135, "OwningProcess": 1652, "Process": "svchost"},
        {"LocalAddress": "::", "LocalPort": 23130, "OwningProcess": 18612, "Process": "Wacom_Tablet"},
        {"LocalAddress": "::1", "LocalPort": 49668, "OwningProcess": 5080, "Process": "jhi_service"},
        {"LocalAddress": "0.0.0.0", "LocalPort": 5040, "OwningProcess": 1328, "Process": "svchost"},
    ]
    rules = [
        {"Name": "ファイルとプリンターの共有 (制限付き) (SMB 入力)", "Ports": "445",
         "Profile": "Public", "Remote": "Any"},
        {"Name": "リモート アシスタンス (DCOM 受信)", "Ports": "135",
         "Profile": "Domain", "Remote": "Any"},
        {"Name": "ネットワーク探索 (WSD イベント受信)", "Ports": "5357",
         "Profile": "Private", "Remote": "LocalSubnet"},
        {"Name": "コア ネットワーク - IPHTTPS (TCP-受信)", "Ports": "IPHTTPSIn",
         "Profile": "Any", "Remote": "Any"},
    ]
    rows = match_listen_to_rules(listeners, rules, ["Public"])
    by_port = {r["port"]: r for r in rows}
    assert set(by_port) == {445, 135, 23130}, by_port     # ::1 と 0.0.0.0 は対象外
    assert by_port[445]["level"] == "warn" and "許可元Any" in by_port[445]["verdict"]
    # 135 の規則は Domain 向けなので、現在 Public では効かない -> 断定しない表現になる
    assert by_port[135]["level"] == "info" and "別プロファイル" in by_port[135]["verdict"]
    assert by_port[23130]["level"] == "good"
    assert rows[0]["port"] == 445                          # 注意すべき行が先頭に来る
    # 数値化できないポート指定 (IPHTTPSIn) は一致に使わない
    assert all("IPHTTPS" not in m["name"] for r in rows for m in r["matched"])
    # プロファイルが Any の規則は現在の種別に関係なく効く
    any_rule = [{"Name": "x", "Ports": "445", "Profile": "Any", "Remote": "Any"}]
    assert match_listen_to_rules(listeners, any_rule, ["Public"])[0]["level"] == "warn"
    assert match_listen_to_rules(listeners, any_rule, [])[0]["level"] == "warn"
    # 許可元が限定されていれば「露出」とは言い切らない
    sub_rule = [{"Name": "x", "Ports": "445", "Profile": "Public", "Remote": "LocalSubnet"}]
    sub_rows = {r["port"]: r for r in match_listen_to_rules(listeners, sub_rule, ["Public"])}
    assert sub_rows[445]["level"] == "info" and sub_rows[135]["level"] == "good"
    assert match_listen_to_rules([], rules, ["Public"]) == []
    assert match_listen_to_rules(listeners, [], ["Public"])[0]["level"] == "good"
    assert _profile_applies("Domain, Private", ["Private"]) is True
    assert _profile_applies("Domain, Private", ["Public"]) is False

    # --- 所見: 欠損だらけでも落ちない & 断定しない ---
    findings = build_findings({})
    assert len(findings) == 4
    for item in findings:
        assert item["ok"] and item["ng"], item      # 「確認できていないこと」が必ず付く
    full = build_findings({
        "addresses": [temp, ll], "privacy": {"UseTemporaryAddresses": "Enabled",
                                             "RandomizeIdentifiers": "Enabled"},
        "path_mtu": {"mtu": 1500, "max_payload": 1452, "method": "m", "host": "h",
                     "link_mtu": 1500, "note": "n"},
        "fragment_check": {"small_size": 1452, "small": True, "large_size": 2000, "large": True},
        "destination_cache": {"entries": 30, "min_pmtu": 1500, "has_reduced": False},
        "firewall": {"profiles": [{"Name": "Public", "Enabled": "True",
                                   "DefaultInboundAction": "NotConfigured"}],
                     "active_profiles": ["Public"], "any_port_rules": 64},
        "exposure": rows, "dns": {"servers": ["2400::1"], "probe": {"server": "2400::1", "ms": 5.0, "answers": 1}},
        "reachability": [{"host": "github.com", "aaaa": None, "connected": False,
                          "connect_ms": None, "error": "AAAAレコードなし"}],
        "rtt": {"host": "google.com", "v4_ms": 8, "v6_ms": 7},
    })
    mtu_item = next(x for x in full if x["title"] == "経路MTUとPMTUD")
    assert any("Packet Too Big" in n for n in mtu_item["ng"])
    fw_item = next(x for x in full if x["title"] == "ファイアウォールと露出")
    assert fw_item["level"] == "warn"           # 全プロファイル有効でも「安全」とは言わない
    assert any("外部からのスキャンは一切行っていない" in n for n in fw_item["ng"])
    assert any("プログラム指定" in n for n in fw_item["ng"])
    addr_item = next(x for x in full if x["title"] == "アドレスとプライバシー")
    assert addr_item["level"] == "good" and any("EUI-64由来" in o for o in addr_item["ok"])
    # EUI-64 があれば bad に上がる
    eui_item = build_findings({"addresses": [classify_address(
        {"IPAddress": "2001:db8::211:22ff:fe33:4455", "PrefixOrigin": "RouterAdvertisement",
         "SuffixOrigin": "Link", "AddressState": "Preferred"})]})[0]
    assert eui_item["level"] == "bad" and any("00:11:22:33:44:55" in o for o in eui_item["ok"])

    print("ipv6 selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import tkinter as tk
    from tkinter import ttk
    import sv_ttk
    root = tk.Tk()
    root.geometry("1200x740")
    root.title("IPv6の詳細監査")
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
    tab = IPv6Tab(frame, ctx)
    if "--auto" in sys.argv:
        root.after(300, tab.start)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
