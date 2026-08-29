#!/usr/bin/env python3
"""自宅ネット回線の実測診断ツール。Wi-Fi/IPv6/遅延/経路/DNS/スループット/バッファブロートを測定し、
results/ 以下に {label}_{timestamp}.json として保存する。同じホストで前後比較する用途を想定。
"""
import argparse
import http.client
import json
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

# 凍結(PyInstaller onefile)時の __file__ は %TEMP%\_MEIxxxx を指し、終了時に消える。
# そこに results/ を作ると診断結果がまるごと捨てられるので、exe本体の隣を基準にする。
BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
RESULTS_DIR = BASE_DIR / "results"

GATEWAY_PLACEHOLDER = "gateway"
TARGETS = {"1.1.1.1": "1.1.1.1", "8.8.8.8": "8.8.8.8"}

CF_HOST = "speed.cloudflare.com"
CHUNK_SIZE = 4_000_000  # Cloudflareの単発サイズ制限/レート制限を避けるための保守的な値。同一TCP接続を使い回して補う


def _setting(dotted, fallback):
    """設定ストアから値を取る。ストアが無い/読めない環境でもこのモジュール単体で動くようにする。"""
    try:
        from settings_store import settings
        value = settings.get(dotted)
        return fallback if value is None else value
    except Exception:
        return fallback


def run(cmd, timeout=20, encoding="cp932"):
    # Windowsのコンソールツール(ping/tracert/powershell)はcp932、netshだけUTF-8を吐く環境依存の癖がある
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, encoding=encoding, errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )


def ps(command, timeout=20):
    r = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], timeout=timeout)
    return r.stdout.strip()


# ---------- Wi-Fi ----------

_WLAN_KEYS = {
    "ssid": ["ssid"],
    "signal_pct": ["signal", "シグナル"],
    "channel": ["channel", "チャネル"],
    "radio_type": ["radio type", "無線の種類"],
    "receive_rate_mbps": ["receive rate", "受信速度", "受信率"],
    "transmit_rate_mbps": ["transmit rate", "送信速度", "送信率"],
    "state": ["state", "状態"],
}


def parse_wlan_interfaces(text):
    if not text.strip() or "not connected" in text.lower() or "実行されていません" in text or "見つかりません" in text:
        return {"available": False, "reason": text.strip() or "no output"}
    fields = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "bssid":
            continue
        for field, variants in _WLAN_KEYS.items():
            if field == "ssid" and key != "ssid":
                continue
            if any(v in key for v in variants):
                fields[field] = value
                break
    if not fields:
        return {"available": False, "reason": "no recognizable interface block"}

    def to_int(v):
        if v is None:
            return None
        m = re.search(r"\d+", v)
        return int(m.group()) if m else None

    return {
        "available": True,
        "ssid": fields.get("ssid"),
        "state": fields.get("state"),
        "signal_pct": to_int(fields.get("signal_pct")),
        "channel": to_int(fields.get("channel")),
        "radio_type": fields.get("radio_type"),
        "receive_rate_mbps": to_int(fields.get("receive_rate_mbps")),
        "transmit_rate_mbps": to_int(fields.get("transmit_rate_mbps")),
        "noise_dbm": None,
        "snr_db": None,
        "channel_width_mhz": None,
        "unavailable_fields_reason": "Windows/netshは信号強度%のみ提供し、ノイズ・SNR・チャネル幅はドライバAPI非公開のため取得不可",
    }


def get_wifi_info():
    try:
        r = run(["netsh", "wlan", "show", "interfaces"], encoding="utf-8")
        return parse_wlan_interfaces(r.stdout if r.returncode == 0 else r.stdout + r.stderr)
    except Exception as e:
        return {"available": False, "reason": f"error: {e}"}


# ---------- IPv6 ----------

def is_global_ipv6(addr):
    a = addr.lower()
    return (a.startswith("2") or a.startswith("3")) and not a.startswith("fe80")


def get_ipv6_info():
    info = {"global_addresses": [], "has_global_address": False,
            "default_route": None, "has_default_route": False,
            "egress_reachable": None}
    try:
        out = ps("Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
                  "Select-Object IPAddress | ConvertTo-Json -Compress")
        if out:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            addrs = [d["IPAddress"] for d in data if "IPAddress" in d]
            info["global_addresses"] = [a for a in addrs if is_global_ipv6(a)]
            info["has_global_address"] = len(info["global_addresses"]) > 0
    except Exception as e:
        info["address_error"] = str(e)

    try:
        out = ps("Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | "
                  "Select-Object NextHop,InterfaceAlias | ConvertTo-Json -Compress")
        if out:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            if data:
                info["default_route"] = data[0]
                info["has_default_route"] = True
    except Exception as e:
        info["route_error"] = str(e)

    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("2606:4700:4700::1111", 53))
        s.close()
        info["egress_reachable"] = True
    except Exception:
        info["egress_reachable"] = False

    return info


# ---------- 遅延 (ping) ----------

def parse_ping_output(text):
    loss_match = re.search(r"\((\d+)%", text)
    ms_values = re.findall(r"=\s*(\d+)\s*ms", text)
    result = {"loss_pct": int(loss_match.group(1)) if loss_match else None,
              "min_ms": None, "max_ms": None, "avg_ms": None}
    if len(ms_values) >= 3:
        mn, mx, av = ms_values[-3:]
        result.update(min_ms=int(mn), max_ms=int(mx), avg_ms=int(av))
    return result


def measure_latency(host, count=10, timeout_ms=1000):
    try:
        r = run(["ping", "-n", str(count), "-w", str(timeout_ms), host], timeout=count * 2 + 10)
        return parse_ping_output(r.stdout)
    except Exception as e:
        return {"error": str(e)}


# ---------- 経路 (traceroute) ----------

def parse_tracert_output(text, max_hops=4):
    hops = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)\s+(.*)$", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        if hop_num > max_hops:
            continue
        rest = m.group(2)
        times = [int(t) for t in re.findall(r"<?(\d+)\s*ms", rest)]
        ip_match = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", rest)
        timed_out = ("*" in rest) and not times
        hops.append({
            "hop": hop_num,
            "ip": ip_match.group(0) if ip_match else None,
            "avg_ms": round(sum(times) / len(times), 1) if times else None,
            "timeout": timed_out,
        })
    return hops


def measure_traceroute(host, max_hops=4):
    try:
        r = run(["tracert", "-d", "-h", str(max_hops), "-w", "800", host], timeout=30)
        return parse_tracert_output(r.stdout, max_hops)
    except Exception as e:
        return {"error": str(e)}


# ---------- IP情報 (ipinfo.io、外部API) ----------

IPINFO_HOST = "ipinfo.io"


def lookup_ip_info(ip=None, _cache={}):
    """ip省略時は自分のグローバルIP情報。プライベートIPは問い合わせず None を返す(bogon判定はAPI側でも行われるが送信自体を避ける)。"""
    if not _setting("advanced.ipinfo_enabled", True):
        return None
    if ip is not None and (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")
                            or ip.startswith("169.254.") or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip)):
        return None
    cache_key = ip or "__self__"
    if cache_key in _cache:
        return _cache[cache_key]
    try:
        conn = http.client.HTTPSConnection(IPINFO_HOST, timeout=5)
        path = f"/{ip}/json" if ip else "/json"
        conn.request("GET", path, headers={"User-Agent": "network-diag/1.0"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        if data.get("bogon"):
            _cache[cache_key] = None
            return None
        info = {"ip": data.get("ip"), "org": data.get("org"), "city": data.get("city"),
                "region": data.get("region"), "country": data.get("country")}
        _cache[cache_key] = info
        return info
    except Exception:
        _cache[cache_key] = None
        return None


def enrich_traceroute_with_ip_info(traceroute_result):
    for hops in traceroute_result.values():
        if not isinstance(hops, list):
            continue
        for hop in hops:
            if hop.get("ip"):
                hop["ip_info"] = lookup_ip_info(hop["ip"])
    return traceroute_result


# ---------- デフォルトゲートウェイ ----------

def get_default_gateway():
    try:
        out = ps("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
                  "Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)")
        return out.strip() or None
    except Exception:
        return None


# ---------- DNS ----------

def dns_query_time(server, domain, timeout=2.0):
    query_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        struct.pack("B", len(part)) + part.encode() for part in domain.split(".")
    ) + b"\x00" + struct.pack(">HH", 1, 1)
    packet = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        start = time.perf_counter()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(512)
        elapsed_ms = (time.perf_counter() - start) * 1000
        resp_id = struct.unpack(">H", data[:2])[0]
        return elapsed_ms if resp_id == query_id else None
    except socket.timeout:
        return None
    finally:
        sock.close()


def measure_dns(server, trials=5):
    times = []
    for _ in range(trials):
        domain = f"{random.randint(100000, 999999)}.example.com"
        t = dns_query_time(server, domain)
        if t is not None:
            times.append(t)
    if not times:
        return {"avg_ms": None, "trials_ok": 0, "trials_total": trials}
    return {"avg_ms": round(sum(times) / len(times), 1), "min_ms": round(min(times), 1),
            "max_ms": round(max(times), 1), "trials_ok": len(times), "trials_total": trials}


# ---------- スループット ----------

def _chunk_size():
    return _setting("throughput.chunk_mb", 4) * 1_000_000


def _speed_host():
    return _setting("targets.speed_host", CF_HOST)


def duration_download(duration_s=None):
    """同一TCP接続(keep-alive)上でチャンクずつ繰り返し取得し、duration_s秒分の実転送量を積算する。
    ハンドシェイクを毎回張り直さず、かつ1リクエストのサイズを小さく保つことでCloudflare側のレート制限を避ける。"""
    if duration_s is None:
        duration_s = _setting("throughput.duration_s", 8)
    chunk = _chunk_size()
    start = time.perf_counter()
    total = 0
    conn = http.client.HTTPSConnection(_speed_host(), timeout=15)
    try:
        while time.perf_counter() - start < duration_s:
            conn.request("GET", f"/__down?bytes={chunk}", headers={"User-Agent": "network-diag/1.0"})
            resp = conn.getresponse()
            data = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            total += len(data)
    finally:
        conn.close()
    return total, time.perf_counter() - start


def measure_throughput_single(duration_s=None):
    try:
        total, elapsed = duration_download(duration_s)
        return {"mbps": round(total * 8 / elapsed / 1e6, 2), "bytes": total, "elapsed_s": round(elapsed, 2)}
    except Exception as e:
        return {"error": str(e)}


def measure_throughput_parallel(n=None, duration_s=None):
    if n is None:
        n = _setting("throughput.parallel_streams", 6)
    try:
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(duration_download, duration_s) for _ in range(n)]
            totals = [f.result()[0] for f in futures]
        elapsed = time.perf_counter() - start
        total_bytes = sum(totals)
        return {"mbps": round(total_bytes * 8 / elapsed / 1e6, 2), "bytes": total_bytes,
                "elapsed_s": round(elapsed, 2), "streams": n}
    except Exception as e:
        return {"error": str(e)}


# ---------- アップロード スループット ----------

def duration_upload(duration_s=None):
    """速度測定サーバの /__up へ同一TCP接続でPOSTし続け、duration_s秒分の実送信量を積算する。"""
    if duration_s is None:
        duration_s = _setting("throughput.duration_s", 8)
    payload = b"\x00" * _chunk_size()
    start = time.perf_counter()
    total = 0
    conn = http.client.HTTPSConnection(_speed_host(), timeout=15)
    try:
        while time.perf_counter() - start < duration_s:
            conn.request("POST", "/__up", body=payload,
                         headers={"User-Agent": "network-diag/1.0", "Content-Length": str(len(payload))})
            resp = conn.getresponse()
            resp.read()
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            total += len(payload)
    finally:
        conn.close()
    return total, time.perf_counter() - start


def measure_upload_single(duration_s=None):
    try:
        total, elapsed = duration_upload(duration_s)
        return {"mbps": round(total * 8 / elapsed / 1e6, 2), "bytes": total, "elapsed_s": round(elapsed, 2)}
    except Exception as e:
        return {"error": str(e)}


def measure_upload_parallel(n=None, duration_s=None):
    if n is None:
        n = _setting("throughput.parallel_streams", 6)
    try:
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(duration_upload, duration_s) for _ in range(n)]
            totals = [f.result()[0] for f in futures]
        elapsed = time.perf_counter() - start
        total_bytes = sum(totals)
        return {"mbps": round(total_bytes * 8 / elapsed / 1e6, 2), "bytes": total_bytes,
                "elapsed_s": round(elapsed, 2), "streams": n}
    except Exception as e:
        return {"error": str(e)}


# ---------- MTU探索 (接続方式の判定に使う) ----------

# ペイロード + IPヘッダ20 + ICMPヘッダ8 = MTU
ICMP_OVERHEAD = 28

MTU_SIGNATURES = {
    1500: "ネイティブEthernet/IPoE (カプセル化なし)",
    1492: "PPPoE (標準)",
    1460: "IPv4 over IPv6 トンネル (IPv6ヘッダ40バイト分。SoftBank IPv6高速ハイブリッド等のIPIP方式)",
    1454: "PPPoE (NTTフレッツ)",
    1442: "DS-Lite / MAP-E系のトンネル",
}


def _mtu_probe(host, payload_size, timeout_ms=2000):
    """DFビット付きpingが断片化されずに通るか。通ればTrue。"""
    r = run(["ping", "-f", "-l", str(payload_size), "-n", "1", "-w", str(timeout_ms), host], timeout=10)
    out = r.stdout
    if "DF" in out or "断片化" in out or "fragmented" in out.lower():
        return False
    return "TTL=" in out or ("応答" in out and "時間" in out) or "time=" in out.lower()


def discover_path_mtu(host=None, low=None, high=None):
    """DFビット付きpingの二分探索で経路MTUを求め、既知のシグネチャから接続方式を推定する。"""
    host = host or _setting("targets.primary", "1.1.1.1")
    low = low or _setting("advanced.mtu_probe_low", 1200)
    high = high or _setting("advanced.mtu_probe_high", 1472)
    try:
        if _mtu_probe(host, high):
            mtu = high + ICMP_OVERHEAD
            return {"mtu": mtu, "max_payload": high, "interpretation": MTU_SIGNATURES.get(mtu, "不明"),
                    "note": "上限値で通過したため、これ以上大きいMTUの可能性もある"}
        if not _mtu_probe(host, low):
            return {"error": f"下限{low}バイトでも通過しないため測定不能(ICMPがブロックされている可能性)"}
        lo, hi = low, high
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if _mtu_probe(host, mid):
                lo = mid
            else:
                hi = mid - 1
        mtu = lo + ICMP_OVERHEAD
        return {"mtu": mtu, "max_payload": lo, "interpretation": MTU_SIGNATURES.get(mtu, "既知のシグネチャに一致せず")}
    except Exception as e:
        return {"error": str(e)}


# ---------- ジッター / MOS (通話・ゲーム品質) ----------

def measure_jitter(host=None, count=None):
    """連続pingのRTT変動からジッターを求め、ITU-T E-model簡易版でMOS値を算出する。"""
    host = host or _setting("targets.primary", "1.1.1.1")
    count = count or _setting("advanced.jitter_samples", 20)
    rtts = []
    lost = 0
    for _ in range(count):
        r = measure_latency(host, count=1, timeout_ms=1000)
        ms = r.get("avg_ms")
        if ms is None:
            lost += 1
        else:
            rtts.append(ms)
    if len(rtts) < 2:
        return {"error": "有効なサンプルが不足", "lost": lost, "count": count}

    # 連続するRTTの差の平均 = ジッター (RFC 3550 の考え方を簡略化したもの)
    diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
    jitter = sum(diffs) / len(diffs)
    avg_rtt = sum(rtts) / len(rtts)
    loss_pct = lost / count * 100

    # E-model簡易版 (Pingtest系で使われる一般的な近似)
    effective_latency = avg_rtt + jitter * 2 + 10
    r_value = 93.2 - (effective_latency / 40 if effective_latency < 160 else (effective_latency - 120) / 10)
    r_value -= loss_pct * 2.5
    r_value = max(0, min(100, r_value))
    mos = 1 + 0.035 * r_value + r_value * (r_value - 60) * (100 - r_value) * 7e-6
    mos = round(max(1.0, min(4.5, mos)), 2)

    if mos >= 4.0:
        quality = "優 (通話・ゲームとも快適)"
    elif mos >= 3.6:
        quality = "良"
    elif mos >= 3.1:
        quality = "可 (通話でやや不満を感じる場合あり)"
    else:
        quality = "不可 (通話品質に明確な問題)"

    return {"jitter_ms": round(jitter, 2), "avg_rtt_ms": round(avg_rtt, 2),
            "loss_pct": round(loss_pct, 1), "samples": len(rtts),
            "mos": mos, "r_value": round(r_value, 1), "quality": quality}


# ---------- 再送率 / NICエラーカウンタ ----------

# 実機の日本語Windowsでは「送信したセグメント」と「再送信されたセグメント」で、前者が後者の部分文字列に
# なる関係にあり、部分一致の正規表現だと取り違える。行単位でラベル全体を突き合わせること。
_TCP_SENT_LABELS = {"送信したセグメント", "Segments Sent"}
_TCP_RETRANS_LABELS = {"再送信されたセグメント", "Segments Retransmitted"}


def parse_netstat_tcp(text):
    sent = retrans = None
    for line in text.splitlines():
        if "=" not in line:
            continue
        label, _, value = line.partition("=")
        label, value = label.strip(), value.strip()
        if not value.isdigit():
            continue
        if label in _TCP_SENT_LABELS:
            sent = int(value)
        elif label in _TCP_RETRANS_LABELS:
            retrans = int(value)
    if sent is None or retrans is None:
        return {}
    return {
        "tcp_segments_sent": sent,
        "tcp_segments_retransmitted": retrans,
        "tcp_retransmit_pct": round(retrans / sent * 100, 3) if sent else None,
    }


def get_link_stats():
    """TCP再送数(netstat -s)とNICのエラー/破棄カウンタ(Get-NetAdapterStatistics)。
    再送率が高い・CRCエラーが増えるのは物理層/無線区間の品質劣化の直接的な証拠になる。"""
    stats = {}
    try:
        r = run(["netstat", "-s", "-p", "tcp"], timeout=15)
        parsed = parse_netstat_tcp(r.stdout)
        stats.update(parsed)
    except Exception as e:
        stats["tcp_error"] = str(e)

    try:
        out = ps("Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | "
                 "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,"
                 "ReceivedDiscardedPackets,ReceivedPacketErrors,OutboundDiscardedPackets,"
                 "OutboundPacketErrors | ConvertTo-Json -Compress", timeout=20)
        if out:
            data = json.loads(out)
            stats["adapters"] = data if isinstance(data, list) else [data]
    except Exception as e:
        stats["adapter_error"] = str(e)

    try:
        out = ps("Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | "
                 "Select-Object Name,LinkSpeed,MediaType,FullDuplex | ConvertTo-Json -Compress", timeout=20)
        if out:
            data = json.loads(out)
            stats["link"] = data if isinstance(data, list) else [data]
    except Exception:
        pass

    return stats


# ---------- NATタイプ判定 (STUN) ----------

STUN_SERVERS = [("stun.l.google.com", 19302), ("stun1.l.google.com", 19302), ("stun.cloudflare.com", 3478)]


def _parse_stun_response(data, magic=0x2112A442):
    """STUN応答から XOR-MAPPED-ADDRESS (無ければ MAPPED-ADDRESS) を取り出す。"""
    if len(data) < 20:
        return None
    msg_len = struct.unpack("!H", data[2:4])[0]
    pos = 20
    end = min(20 + msg_len, len(data))
    while pos + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[pos:pos + 4])
        value = data[pos + 4:pos + 4 + attr_len]
        if attr_type == 0x0020 and len(value) >= 8:  # XOR-MAPPED-ADDRESS
            xport = struct.unpack("!H", value[2:4])[0] ^ (magic >> 16)
            xip = struct.unpack("!I", value[4:8])[0] ^ magic
            ip = socket.inet_ntoa(struct.pack("!I", xip))
            return ip, xport
        if attr_type == 0x0001 and len(value) >= 8:  # MAPPED-ADDRESS (旧仕様)
            port_v = struct.unpack("!H", value[2:4])[0]
            ip = socket.inet_ntoa(value[4:8])
            return ip, port_v
        pos += 4 + attr_len + ((4 - attr_len % 4) % 4)
    return None


def _stun_binding_request(server, port, sock=None, timeout=3.0):
    """RFC 5389 のBinding Requestを投げ、外部IP:portを得る。
    sock を渡すとそのソケット(=同一の送信元ポート)を使い回す。NAT判定にはこれが必須。"""
    magic = 0x2112A442
    tid = bytes(random.getrandbits(8) for _ in range(12))
    packet = struct.pack("!HHI12s", 0x0001, 0, magic, tid)
    own_sock = sock is None
    if own_sock:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(2048)
    finally:
        if own_sock:
            sock.close()
    return _parse_stun_response(data, magic)


def classify_nat(observations):
    """同一送信元ポートから複数サーバを見た結果からNATのマッピング方式を判定する。"""
    if not observations:
        return {"error": "STUNサーバに到達できず判定不能(UDPがブロックされている可能性)"}
    if len(observations) == 1:
        return {"nat_type": "判定不能 (1サーバのみ応答)", "observations": observations}

    ports = {o["external_port"] for o in observations}
    ips = {o["external_ip"] for o in observations}
    local_ports = {o["local_port"] for o in observations}

    if len(ports) == 1:
        external_port = next(iter(ports))
        preserved = len(local_ports) == 1 and external_port in local_ports
        nat_type = ("Cone NAT / Endpoint-Independent Mapping"
                    " (宛先が変わっても同じ外部ポート。P2P・ゲーム・通話に有利)")
        if preserved:
            nat_type += " ※送信元ポートがそのまま外部ポートになるポート保存型"
    else:
        nat_type = ("Symmetric NAT (同じ送信元ポートでも宛先ごとに外部ポートが変わる。"
                    "P2P接続やゲームのマッチングで不利)")

    return {"nat_type": nat_type,
            "external_ip": next(iter(ips)) if len(ips) == 1 else sorted(ips),
            "external_ports": sorted(ports), "local_ports": sorted(local_ports),
            "observations": observations}


def detect_nat_type():
    """NATのマッピング方式を判定する。

    重要: 判定は必ず「同一の送信元ポート」から複数のSTUNサーバへ問い合わせて行うこと。
    サーバごとに新しいUDPソケットを作ると、OSが毎回別のエフェメラルポートを割り当てるため、
    ポート保存型のCone NATでも外部ポートが変わって見え、Symmetric NATと誤判定する
    (実際にこの誤りを踏んだ。送信元ポートを固定したら全サーバで同一ポートが返り Cone と判明)。
    """
    observations = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))  # 一度だけポートを確保し、全サーバでこれを使い回す
        local_port = sock.getsockname()[1]
        for server, port in STUN_SERVERS:
            try:
                mapped = _stun_binding_request(server, port, sock=sock)
            except Exception:
                continue
            if mapped:
                observations.append({"server": server, "local_port": local_port,
                                     "external_ip": mapped[0], "external_port": mapped[1]})
    finally:
        sock.close()
    return classify_nat(observations)


# ---------- IPv4 / IPv6 の対決測定 ----------

class _FamilyHTTPSConnection(http.client.HTTPSConnection):
    """アドレスファミリを固定してTCP接続するHTTPSConnection。
    IPv4とIPv6で同じ宛先を同条件で測り分けるために使う。"""

    def __init__(self, host, family, **kwargs):
        super().__init__(host, **kwargs)
        self._family = family

    # 注意: http.client は __init__ で self._create_connection = socket.create_connection を
    # インスタンス属性として設定するため、同名メソッドを定義しても隠されて呼ばれない。
    # (これで実際にIPv4指定のはずが全部IPv6で通信していた。) 別名にして確実に自分の実装を通す。
    def _connect_with_family(self):
        last_err = None
        for af, socktype, proto, _, sa in socket.getaddrinfo(
                self.host, self.port, self._family, socket.SOCK_STREAM):
            sock = socket.socket(af, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                sock.connect(sa)
                return sock
            except OSError as e:
                last_err = e
                sock.close()
        raise last_err or OSError("接続先が見つかりません")

    def connect(self):
        self.sock = self._connect_with_family()
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host)


def _download_family(family, duration_s):
    start = time.perf_counter()
    total = 0
    conn = _FamilyHTTPSConnection(CF_HOST, family, timeout=15)
    try:
        conn.connect()
        peer = conn.sock.getpeername()[0]
        while time.perf_counter() - start < duration_s:
            conn.request("GET", f"/__down?bytes={CHUNK_SIZE}", headers={"User-Agent": "network-diag/1.0"})
            resp = conn.getresponse()
            data = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            total += len(data)
    finally:
        conn.close()
    return total, time.perf_counter() - start, peer


def compare_ipv4_ipv6(duration_s=6):
    """同じ宛先へIPv4とIPv6で別々に接続してスループットとRTTを比べる。

    この回線のIPv4はIPv4 over IPv6トンネル(経路MTU1460)を通り、IPv6はネイティブ(1500)。
    トンネルのカプセル化オーバーヘッドが実効速度に出るかを見る目的。
    """
    result = {}
    for family, key in ((socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")):
        entry = {}
        try:
            infos = socket.getaddrinfo(CF_HOST, 443, family, socket.SOCK_STREAM)
            entry["address"] = infos[0][4][0]
            # TCPハンドシェイク時間を3回測って中央値を取る(ICMPを使わないのでv6でも同条件)
            handshakes = []
            for _ in range(3):
                t0 = time.perf_counter()
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(5)
                try:
                    s.connect(infos[0][4])
                    handshakes.append((time.perf_counter() - t0) * 1000)
                finally:
                    s.close()
            handshakes.sort()
            entry["tcp_handshake_ms"] = round(handshakes[len(handshakes) // 2], 1)
        except Exception as e:
            result[key] = {"error": f"接続不可: {e}"}
            continue

        try:
            total, elapsed, peer = _download_family(family, duration_s)
            entry["peer"] = peer
            entry["mbps"] = round(total * 8 / elapsed / 1e6, 2)
            entry["bytes"] = total
        except Exception as e:
            entry["error"] = str(e)
        result[key] = entry

    v4, v6 = result.get("ipv4", {}), result.get("ipv6", {})
    if v4.get("mbps") and v6.get("mbps"):
        diff = v6["mbps"] - v4["mbps"]
        result["comparison"] = {
            "faster": "IPv6" if diff > 0 else "IPv4",
            "diff_mbps": round(abs(diff), 2),
            "diff_pct": round(abs(diff) / min(v4["mbps"], v6["mbps"]) * 100, 1),
            "note": "IPv4がIPv4 over IPv6トンネル経由の場合、カプセル化の分だけIPv6が速く出ることがある。"
                    "ただしCDNのサーバ側条件が異なる可能性もあるため、単発の差だけで断定はできない。",
        }
    return result


# ---------- 時刻同期 (NTP) ----------

NTP_SERVERS = ["ntp.nict.jp", "time.cloudflare.com", "time.windows.com"]
NTP_EPOCH_OFFSET = 2_208_988_800  # 1900-01-01 から 1970-01-01 までの秒数


def _ntp_query(server, timeout=4.0):
    """NTPサーバへ問い合わせ、(オフセット秒, 往復遅延秒) を返す。

    offset = ((t1-t0) + (t2-t3)) / 2 で、正なら『サーバの時刻がこちらより先』
    = こちらの時計が遅れている。負ならこちらが進んでいる。
    正しい時刻を得るには 現在時刻 + offset とすればよい。
    """
    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.time()
        sock.sendto(packet, (server, 123))
        data, _ = sock.recvfrom(48)
        t3 = time.time()
    finally:
        sock.close()
    if len(data) < 48:
        raise ValueError("NTP応答が短すぎます")
    fields = struct.unpack("!12I", data)
    t1 = fields[8] + fields[9] / 2 ** 32 - NTP_EPOCH_OFFSET   # サーバ受信時刻
    t2 = fields[10] + fields[11] / 2 ** 32 - NTP_EPOCH_OFFSET  # サーバ送信時刻
    offset = ((t1 - t0) + (t2 - t3)) / 2
    delay = (t3 - t0) - (t2 - t1)
    return offset, delay


def measure_time_sync(servers=None):
    """複数のNTPサーバとの時刻差を測る。1台だけだとサーバ側の異常と区別できないため複数使う。"""
    servers = servers or NTP_SERVERS
    samples = []
    for server in servers:
        try:
            offset, delay = _ntp_query(server)
            samples.append({"server": server, "offset_ms": round(offset * 1000, 1),
                            "rtt_ms": round(delay * 1000, 1)})
        except Exception as e:
            samples.append({"server": server, "error": str(e)})

    offsets = [s["offset_ms"] for s in samples if "offset_ms" in s]
    if not offsets:
        return {"error": "どのNTPサーバにも到達できませんでした(UDP 123 が塞がれている可能性)",
                "samples": samples}

    offsets.sort()
    median = offsets[len(offsets) // 2]
    spread = max(offsets) - min(offsets)
    magnitude = abs(median)
    if magnitude < 100:
        verdict = "正常 (100ms未満)"
    elif magnitude < 1000:
        verdict = "やや大きい (100ms以上1秒未満)。通常Windowsはこの範囲に収める"
    elif magnitude < 60_000:
        verdict = "大きい (1秒以上)。TLS証明書の検証やゲーム・認証で問題が出うる"
    else:
        verdict = "深刻 (1分以上)。多くのHTTPS接続や二要素認証が失敗する"

    return {
        "offset_ms": median, "abs_offset_ms": round(magnitude, 1),
        "server_spread_ms": round(spread, 1), "samples": samples,
        # offsetが正 = サーバの方が先の時刻 = こちらが遅れている
        "direction": "こちらの時計が遅れている" if median > 0 else "こちらの時計が進んでいる",
        "correct_time_hint": f"正しい時刻 = 現在の表示 {'+' if median > 0 else '-'} {round(magnitude)}ms",
        "verdict": verdict,
        "agreement": "複数サーバの値が一致しており実在の誤差" if spread < 200 and len(offsets) > 1
                     else "サーバ間で値がばらついており、経路の遅延ゆらぎの影響を受けている可能性",
        "note": "オフセットはNTPの標準式で算出。ズレが大きい場合は w32tm /resync で再同期できる。",
    }


# ---------- QUIC / HTTP3 の疎通 ----------

QUIC_TEST_HOSTS = ["cloudflare.com", "www.google.com"]
QUIC_UNKNOWN_VERSION = 0x1A2A3A4A  # 未知バージョン: RFC9000上サーバはVersion Negotiationを返す義務がある


def probe_quic(host, timeout=4.0):
    """UDP 443 でQUICが通るかを確認する。

    正しいInitialパケットを組むにはTLS ClientHelloの暗号化が要り、不正なパケットは黙って捨てられる
    (実際に自作パケットで無応答になり『QUICが塞がれている』と誤診しかけた)。
    そこで未知バージョンを送り、Version Negotiation応答を強制することで到達性だけを確かめる。
    """
    try:
        addr = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except Exception as e:
        return {"host": host, "error": f"名前解決に失敗: {e}"}

    dcid, scid = random.randbytes(8), random.randbytes(8)
    packet = bytes([0xC0]) + struct.pack("!I", QUIC_UNKNOWN_VERSION)
    packet += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    packet += b"\x00" * (1200 - len(packet))  # Initialは1200バイト以上でないと処理されない

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        start = time.perf_counter()
        sock.sendto(packet, addr)
        data, _ = sock.recvfrom(2048)
        rtt_ms = round((time.perf_counter() - start) * 1000, 1)
    except socket.timeout:
        return {"host": host, "reachable": False,
                "note": "無応答。UDP 443 が塞がれているか、経路上で落とされている可能性"}
    except Exception as e:
        return {"host": host, "reachable": False, "error": str(e)}
    finally:
        sock.close()

    is_vn = bool(data[0] & 0x80) and struct.unpack("!I", data[1:5])[0] == 0
    return {"host": host, "reachable": True, "version_negotiation": is_vn,
            "rtt_ms": rtt_ms, "response_bytes": len(data), "server_ip": addr[0]}


def check_quic():
    results = [probe_quic(h) for h in QUIC_TEST_HOSTS]
    ok = [r for r in results if r.get("reachable")]
    return {
        "hosts": results,
        "usable": len(ok) > 0,
        "verdict": ("QUIC(UDP 443)は通っている。HTTP/3が利用可能" if len(ok) == len(results)
                    else "一部のホストのみ応答。経路やサーバ側の事情の可能性" if ok
                    else "どのホストからも応答なし。ルーターやFWがUDP 443を塞いでいる可能性がある。"
                         "その場合ブラウザはTCPへフォールバックするため通信自体は続くが、"
                         "HTTP/3の利点(接続確立の速さ・パケットロス耐性)が得られない"),
    }


# ---------- IPブラックリスト照会 (DNSBL) ----------

# 戻り値のAレコードで意味が変わる。家庭用回線がPBLに載るのは正常なので、区別せず「掲載」と出さないこと。
DNSBL_ZONES = {
    "zen.spamhaus.org": {
        "127.0.0.2": ("SBL", "スパム送信元として登録", "bad"),
        "127.0.0.3": ("CSS", "スパム送信元(自動検出)として登録", "bad"),
        "127.0.0.4": ("XBL", "感染・踏み台として登録", "bad"),
        "127.0.0.9": ("SBL", "経路ハイジャック等の登録", "bad"),
        "127.0.0.10": ("PBL", "家庭用/動的IP。直接メール送信すべきでないIPという登録で、"
                              "家庭回線では正常。迷惑行為の記録ではない", "info"),
        "127.0.0.11": ("PBL", "家庭用/動的IP(ISP申告)。家庭回線では正常", "info"),
    },
    "bl.spamcop.net": {},
    "b.barracudacentral.org": {},
    "dnsbl.sorbs.net": {},
}


def check_dnsbl(ip=None):
    """自分の公開IPが各種DNSBLに載っているかをDNSで照会する(APIキー不要)。"""
    if ip is None:
        info = lookup_ip_info() or {}
        ip = info.get("ip")
    if not ip or ":" in ip:
        return {"error": "IPv4のグローバルアドレスを特定できませんでした", "ip": ip}

    reversed_ip = ".".join(reversed(ip.split(".")))
    entries = []
    for zone, codes in DNSBL_ZONES.items():
        query = f"{reversed_ip}.{zone}"
        try:
            answers = sorted({r[4][0] for r in socket.getaddrinfo(query, None, socket.AF_INET)})
        except socket.gaierror:
            entries.append({"zone": zone, "listed": False})
            continue
        except Exception as e:
            entries.append({"zone": zone, "error": str(e)})
            continue
        details = [codes.get(a, ("不明", f"応答コード {a} の意味は未対応", "warn")) for a in answers]
        entries.append({
            "zone": zone, "listed": True, "codes": answers,
            "kinds": [d[0] for d in details],
            "explanations": [d[1] for d in details],
            "severity": "bad" if any(d[2] == "bad" for d in details)
                        else "warn" if any(d[2] == "warn" for d in details) else "info",
        })

    problems = [e for e in entries if e.get("severity") == "bad"]
    unknown = [e for e in entries if e.get("severity") == "warn"]
    if problems:
        verdict = "迷惑行為の記録として掲載されています。メール送信や一部サービスで拒否される可能性があります"
    elif unknown:
        verdict = "意味を判定できない掲載があります。内容を確認してください"
    elif any(e.get("listed") for e in entries):
        verdict = "掲載はありますが、家庭用回線として正常な種別のみです(問題ではありません)"
    else:
        verdict = "どのリストにも掲載されていません"

    return {"ip": ip, "entries": entries, "has_problem": bool(problems), "verdict": verdict}


# ---------- バッファブロート ----------

def measure_bufferbloat(host=None, idle_count=None, load_streams=None, load_duration_s=None):
    host = host or _setting("targets.primary", "1.1.1.1")
    idle_count = idle_count or _setting("bufferbloat.idle_count", 10)
    load_streams = load_streams or _setting("bufferbloat.load_streams", 6)
    load_duration_s = load_duration_s or _setting("bufferbloat.load_duration_s", 10)
    idle = measure_latency(host, count=idle_count)

    stop_flag = threading.Event()

    def load_worker():
        end_time = time.perf_counter() + load_duration_s
        while time.perf_counter() < end_time and not stop_flag.is_set():
            remaining = end_time - time.perf_counter()
            if remaining <= 0:
                break
            try:
                duration_download(duration_s=min(2, remaining))
            except Exception:
                break

    threads = [threading.Thread(target=load_worker) for _ in range(load_streams)]
    for t in threads:
        t.start()
    time.sleep(1)  # 負荷が立ち上がるのを待つ
    loaded = measure_latency(host, count=idle_count)
    stop_flag.set()
    for t in threads:
        t.join(timeout=5)

    rpm_approx = None
    if loaded.get("avg_ms"):
        rpm_approx = round(60000 / loaded["avg_ms"])

    increase_ms = None
    increase_pct = None
    if idle.get("avg_ms") and loaded.get("avg_ms"):
        increase_ms = loaded["avg_ms"] - idle["avg_ms"]
        increase_pct = round(increase_ms / idle["avg_ms"] * 100, 1)

    return {
        "idle_latency": idle,
        "loaded_latency": loaded,
        "increase_ms": increase_ms,
        "increase_pct": increase_pct,
        "rpm_approx": rpm_approx,
        "rpm_note": "Appleの networkQuality はWindowsに存在しないための近似値。"
                    "60000/負荷時平均RTTで算出した簡易指標であり公式RPM値とは計算方法が異なる。",
    }


# ---------- 自己テスト (ネットワーク不要) ----------

def test_parsers():
    r = parse_ping_output(
        "\n".join([
            "192.168.1.1 の ping 統計:",
            "    パケット数: 送信 = 10、受信 = 10、損失 = 0 (0% の損失)、",
            "ラウンド トリップの概算時間 (ミリ秒):",
            "    最小 = 1ms、最大 = 5ms、平均 = 2ms",
        ])
    )
    assert r == {"loss_pct": 0, "min_ms": 1, "max_ms": 5, "avg_ms": 2}, r

    r2 = parse_ping_output("Request timed out.\n" * 4 + "    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),")
    assert r2["loss_pct"] == 100 and r2["avg_ms"] is None, r2

    hops = parse_tracert_output(
        "  1     1 ms    <1 ms    <1 ms  192.168.1.1\n"
        "  2     *        *        *     要求がタイムアウトしました。\n"
        "  3    10 ms     9 ms    11 ms  10.0.0.1\n"
    )
    assert hops[0] == {"hop": 1, "ip": "192.168.1.1", "avg_ms": 1.0, "timeout": False}, hops[0]
    assert hops[1]["timeout"] is True and hops[1]["ip"] is None, hops[1]
    assert hops[2]["ip"] == "10.0.0.1" and hops[2]["avg_ms"] == 10.0, hops[2]

    wlan = parse_wlan_interfaces(
        "名前                   : Wi-Fi\n"
        "状態                   : 接続済み\n"
        "SSID                  : MyNet\n"
        "無線の種類             : 802.11ac\n"
        "チャネル               : 36\n"
        "受信速度 (Mbps)        : 866\n"
        "送信速度 (Mbps)        : 866\n"
        "シグナル               : 88%\n"
    )
    assert wlan["available"] is True
    assert wlan["ssid"] == "MyNet" and wlan["channel"] == 36 and wlan["signal_pct"] == 88

    no_wlan = parse_wlan_interfaces("ワイヤレス自動構成サービス (wlansvc) が実行されていません。")
    assert no_wlan["available"] is False

    # netstat: 「送信したセグメント」が「再送信されたセグメント」の部分文字列になる罠の回帰テスト
    netstat_ja = "\n".join([
        "IPv4 の TCP 統計", "",
        "  受信したセグメント               = 6940027",
        "  送信したセグメント               = 8555897",
        "  再送信されたセグメント           = 312051",
    ])
    tcp = parse_netstat_tcp(netstat_ja)
    assert tcp["tcp_segments_sent"] == 8555897, tcp
    assert tcp["tcp_segments_retransmitted"] == 312051, tcp
    assert tcp["tcp_retransmit_pct"] == 3.647, tcp

    netstat_en = "  Segments Sent                       = 1000\n  Segments Retransmitted              = 10\n"
    tcp_en = parse_netstat_tcp(netstat_en)
    assert tcp_en["tcp_retransmit_pct"] == 1.0, tcp_en
    assert parse_netstat_tcp("no numbers here") == {}

    # flatten_metrics: 新項目が無い古い結果でも落ちず "-" で埋まること
    old_result = {"label": "old", "timestamp": "2026-01-01T00:00:00",
                  "throughput": {"single": {"error": "HTTP 429"}}}
    flat = flatten_metrics(old_result)
    assert flat["ラベル"] == "old" and flat["経路MTU"] == "-" and flat["上り単一Mbps"] == "-", flat
    assert flat["下り単一Mbps"] == "-", flat  # error のときは mbps キーが無い
    assert flatten_metrics({})["ISP"] == "-"

    # MTUシグネチャ: 実測で確定した1460(IPv4 over IPv6)が引けること
    assert "IPv6" in MTU_SIGNATURES[1460]
    assert MTU_SIGNATURES[1492].startswith("PPPoE")

    # グレード判定
    perfect = {
        "throughput": {"parallel6": {"mbps": 950}}, "upload": {"parallel6": {"mbps": 900}},
        "latency": {"1.1.1.1": {"avg_ms": 5}}, "jitter": {"jitter_ms": 1},
        "bufferbloat": {"loaded_latency": {"loss_pct": 0}, "increase_pct": 10},
        "link_stats": {"tcp_retransmit_pct": 0.1},
    }
    assert grade_connection(perfect)["grade"] == "A", grade_connection(perfect)

    awful = {
        "throughput": {"parallel6": {"mbps": 5}}, "upload": {"parallel6": {"mbps": 2}},
        "latency": {"1.1.1.1": {"avg_ms": 300}}, "jitter": {"jitter_ms": 50},
        "bufferbloat": {"loaded_latency": {"loss_pct": 30}, "increase_pct": 900},
        "link_stats": {"tcp_retransmit_pct": 15},
    }
    assert grade_connection(awful)["grade"] == "F", grade_connection(awful)

    # 測定できなかった項目は満点から除外され、残りだけで正規化される
    partial = grade_connection({"latency": {"1.1.1.1": {"avg_ms": 5}}})
    assert partial["possible"] == 15 and partial["grade"] == "A", partial
    assert any(b["点"] is None for b in partial["breakdown"]), partial

    empty = grade_connection({})
    assert empty["grade"] == "?" and empty["score"] is None, empty

    # NAT判定: 同一送信元ポートで外部ポートが揃えばCone、変われば本物のSymmetric。
    # かつて「サーバごとに別ソケット→別の送信元ポート」で測り、ポート保存型のConeを
    # Symmetricと誤判定した。local_portが揃っていることが判定の前提である点を固定する。
    cone = classify_nat([
        {"server": "a", "local_port": 30727, "external_ip": "126.1.32.112", "external_port": 30727},
        {"server": "b", "local_port": 30727, "external_ip": "126.1.32.112", "external_port": 30727},
        {"server": "c", "local_port": 30727, "external_ip": "126.1.32.112", "external_port": 30727},
    ])
    assert cone["nat_type"].startswith("Cone NAT"), cone
    assert "ポート保存型" in cone["nat_type"], cone
    assert cone["external_ip"] == "126.1.32.112" and cone["external_ports"] == [30727], cone

    cone_no_preserve = classify_nat([
        {"server": "a", "local_port": 40000, "external_ip": "1.2.3.4", "external_port": 55555},
        {"server": "b", "local_port": 40000, "external_ip": "1.2.3.4", "external_port": 55555},
    ])
    assert cone_no_preserve["nat_type"].startswith("Cone NAT"), cone_no_preserve
    assert "ポート保存型" not in cone_no_preserve["nat_type"], cone_no_preserve

    symmetric = classify_nat([
        {"server": "a", "local_port": 40000, "external_ip": "1.2.3.4", "external_port": 55555},
        {"server": "b", "local_port": 40000, "external_ip": "1.2.3.4", "external_port": 55556},
    ])
    assert symmetric["nat_type"].startswith("Symmetric NAT"), symmetric

    assert "error" in classify_nat([])
    assert classify_nat([{"server": "a", "local_port": 1, "external_ip": "1.2.3.4",
                          "external_port": 1}])["nat_type"].startswith("判定不能")

    # STUN応答のパース(実際のXOR-MAPPED-ADDRESSの構造)
    magic = 0x2112A442
    want_ip, want_port = "126.1.32.112", 30727
    xor_port = want_port ^ (magic >> 16)
    xor_ip = struct.unpack("!I", socket.inet_aton(want_ip))[0] ^ magic
    attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 0x01, xor_port, xor_ip)
    resp = struct.pack("!HHI12s", 0x0101, len(attr), magic, b"\x00" * 12) + attr
    assert _parse_stun_response(resp) == (want_ip, want_port), _parse_stun_response(resp)
    assert _parse_stun_response(b"\x00" * 8) is None

    # アドレスファミリ固定: http.client が __init__ で _create_connection をインスタンス属性として
    # 設定するため、同名メソッドの override は効かない。別名メソッドが使われていることを固定する。
    assert hasattr(_FamilyHTTPSConnection, "_connect_with_family")
    _probe = _FamilyHTTPSConnection(CF_HOST, socket.AF_INET)
    assert _probe._family == socket.AF_INET
    # インスタンス属性 _create_connection は http.client 由来のものが入っている(= override不可)
    assert _probe._create_connection is socket.create_connection, \
        "http.clientの実装が変わった可能性あり。ファミリ固定の方式を見直すこと"
    assert type(_probe).connect is not http.client.HTTPSConnection.connect, "connectがoverrideされていない"

    # NTPのオフセット符号: 正=こちらが遅れている / 負=こちらが進んでいる。
    # 実測が -452.6ms のとき「進んでいる」と読むのが正しい(ここを口頭で言い間違えた)。
    _fake = [("a", -0.4526, 0.016), ("b", -0.4530, 0.018), ("c", -0.4515, 0.017)]
    _saved = globals()["_ntp_query"]
    try:
        globals()["_ntp_query"] = lambda s, timeout=4.0: next(
            (o, d) for n, o, d in _fake if n == s)
        ts = measure_time_sync(servers=["a", "b", "c"])
        assert ts["offset_ms"] == -452.6, ts
        assert ts["direction"] == "こちらの時計が進んでいる", ts
        assert "1秒未満" in ts["verdict"], ts
        assert ts["server_spread_ms"] == 1.5, ts
        assert "一致" in ts["agreement"], ts

        globals()["_ntp_query"] = lambda s, timeout=4.0: (0.02, 0.01)
        assert measure_time_sync(servers=["a"])["verdict"].startswith("正常")
        globals()["_ntp_query"] = lambda s, timeout=4.0: (120.0, 0.01)
        assert "深刻" in measure_time_sync(servers=["a"])["verdict"]

        def _boom(s, timeout=4.0):
            raise OSError("unreachable")
        globals()["_ntp_query"] = _boom
        assert "error" in measure_time_sync(servers=["a", "b"])
    finally:
        globals()["_ntp_query"] = _saved

    # DNSBL: PBL(127.0.0.10)は家庭用回線として正常。問題として扱わないこと。
    zen = DNSBL_ZONES["zen.spamhaus.org"]
    assert zen["127.0.0.10"][2] == "info" and zen["127.0.0.11"][2] == "info"
    assert zen["127.0.0.2"][2] == "bad" and zen["127.0.0.4"][2] == "bad"
    assert check_dnsbl(ip="2606:4700::1111")["error"], "IPv6は弾くこと"

    # QUIC: 未知バージョンを送ってVersion Negotiationを誘発する仕様を固定する
    assert QUIC_UNKNOWN_VERSION not in (0, 1), "既知バージョンだとVNが返らない"

    # 設定ストア連携: 値を変えると測定パラメータに反映されること。
    # また settings_store が無い環境でも fallback で動くこと。
    from settings_store import settings as _s
    _before = _s.get("general.contract_mbps")
    try:
        _s.set("general.contract_mbps", 500)
        # 契約500Mbps基準なら下り292Mbpsは達成率58.4% → 「40以上」の帯で16点(1000基準だと29.2%で11点)
        _sample = {"throughput": {"parallel6": {"mbps": 292}}}
        assert grade_connection(_sample)["breakdown"][0]["点"] == 16, grade_connection(_sample)["breakdown"][0]
        # 明示引数は設定より優先される
        assert grade_connection(_sample, contract_mbps=1000)["breakdown"][0]["点"] == 11
        _s.set("targets.primary", "9.9.9.9")
        _s.set("targets.secondary", "9.9.9.9")
        assert list(active_targets()) == ["9.9.9.9"], active_targets()  # 重複は畳まれる
    finally:
        _s.reset_section("targets")
        _s.set("general.contract_mbps", _before)
    assert _setting("nosuch.key", "fb") == "fb"

    # 結果一覧のフィルタ: 各タブが吐く独自JSONを診断結果として拾わないこと
    # 各タブが results/ に吐く独自JSONは、フル診断の結果一覧に混ざってはいけない。
    # (混ざるとレポートや総合診断が中身の無いファイルにグレードを付けてしまう)
    for name in ("dnsaudit_20260823.json", "lanscan_x.json", "geomap_x.json", "capture_x.json",
                 "atlas_x.json", "ipv6_x.json", "bandwidth_x.json", "topology_x.json",
                 "services_x.json", "tuning_x.json", "advice_x.json"):
        assert name.startswith(NON_DIAGNOSTIC_PREFIXES), name
    for name in ("baseline_20260823.json", "full_v2_20260823.json", "after_fix_1.json"):
        assert not name.startswith(NON_DIAGNOSTIC_PREFIXES), name

    # 実測相当の値ならA〜Fの中間に落ちること(極端な値だけでなく現実の値でも壊れないこと)
    actual = grade_connection({
        "throughput": {"parallel6": {"mbps": 291.8}}, "upload": {"parallel6": {"mbps": 251.7}},
        "latency": {"1.1.1.1": {"avg_ms": 8}}, "jitter": {"jitter_ms": 1.84},
        "bufferbloat": {"loaded_latency": {"loss_pct": 20}, "increase_pct": 75},
        "link_stats": {"tcp_retransmit_pct": 3.6},
    })
    assert actual["grade"] in "BCDE", actual
    assert actual["comment"].startswith("最も足を引っ張っている項目"), actual

    print("selftest: OK")


# ---------- メイン ----------

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="自宅ネット回線 実測診断ツール")
    parser.add_argument("label", nargs="?", help="この測定のラベル (例: before, after_ipoe)")
    parser.add_argument("--selftest", action="store_true", help="パーサーの自己テストのみ実行して終了")
    args = parser.parse_args()

    if args.selftest:
        test_parsers()
        return

    if not args.label:
        parser.error("labelを指定してください (--selftest を除く)")

    result = run_diagnostics(args.label, progress=lambda msg: print(msg, flush=True))
    out_path = save_result(result)

    print(f"\n保存先: {out_path}")
    print(json.dumps(result, ensure_ascii=False, indent=2))


TOTAL_STEPS = 16


def active_targets():
    """設定で指定された測定先。重複は除く。"""
    hosts = [_setting("targets.primary", "1.1.1.1"), _setting("targets.secondary", "8.8.8.8")]
    return {h: h for h in dict.fromkeys(h for h in hosts if h)}


def run_diagnostics(label, progress=lambda msg: None):
    """全項目を計測してresult dictを返す。progressにステップ名を都度渡す(GUI/CLI共用)。"""
    result = {"label": label, "timestamp": datetime.now().isoformat(timespec="seconds")}
    step = [0]

    def step_msg(text):
        step[0] += 1
        progress(f"[{step[0]}/{TOTAL_STEPS}] {text}")

    step_msg("Wi-Fi情報...")
    result["wifi"] = get_wifi_info()

    step_msg("IPv6情報...")
    result["ipv6"] = get_ipv6_info()

    step_msg("デフォルトゲートウェイ検出...")
    gateway = get_default_gateway()
    result["gateway_ip"] = gateway

    targets = active_targets()

    step_msg(f"遅延測定 (ゲートウェイ/{'/'.join(targets)})...")
    latency = {}
    if gateway:
        latency["gateway"] = measure_latency(gateway)
    for name, host in targets.items():
        latency[name] = measure_latency(host)
    result["latency"] = latency

    step_msg("経路 (traceroute 先頭4ホップ) とISP情報照会(ipinfo.io)...")
    traceroute = {name: measure_traceroute(host) for name, host in targets.items()}
    result["traceroute"] = enrich_traceroute_with_ip_info(traceroute)
    result["public_ip_info"] = lookup_ip_info()

    step_msg("DNS応答時間比較...")
    dns = {}
    if gateway:
        dns["router"] = measure_dns(gateway)
    for name, host in targets.items():
        dns[name] = measure_dns(host)
    result["dns"] = dns

    step_msg("MTU探索 (接続方式の判定)...")
    result["path_mtu"] = discover_path_mtu()

    step_msg("ジッター / MOS (通話・ゲーム品質)...")
    result["jitter"] = measure_jitter()

    step_msg("再送率 / NICエラーカウンタ...")
    result["link_stats"] = get_link_stats()

    step_msg("NATタイプ判定 (STUN)...")
    result["nat"] = detect_nat_type()

    step_msg("下りスループット (単一接続 / 6並列)...")
    result["throughput"] = {
        "single": measure_throughput_single(),
        "parallel6": measure_throughput_parallel(),
    }

    step_msg("上りスループット (単一接続 / 6並列)...")
    result["upload"] = {
        "single": measure_upload_single(),
        "parallel6": measure_upload_parallel(),
    }

    step_msg("IPv4 / IPv6 の対決測定...")
    result["ip_version_compare"] = compare_ipv4_ipv6()

    step_msg("時刻同期のズレ (NTP)...")
    result["time_sync"] = measure_time_sync()

    step_msg("QUIC / HTTP3 の疎通...")
    result["quic"] = check_quic()

    step_msg("IPブラックリスト照会 (DNSBL)...")
    result["dnsbl"] = check_dnsbl()

    step_msg("バッファブロート...")
    result["bufferbloat"] = measure_bufferbloat()

    result["grade"] = grade_connection(result)
    return result


def save_result(result):
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = RESULTS_DIR / f"{result['label']}_{ts}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


# results/ には各タブが独自のJSONも吐くので、フル診断の結果だけを拾えるよう接頭辞で除外する
NON_DIAGNOSTIC_PREFIXES = ("lanscan_", "watchdog_", "pathmon_", "report_", "ping_log_",
                           "dnsaudit_", "geomap_", "portcheck_", "capture_",
                           "atlas_", "ipv6_", "bandwidth_", "topology_", "services_",
                           "tuning_", "advice_", "trend_")


# ---------- 接続品質グレード ----------

# 各項目の閾値: (指標名, 値の取り出し方, [(閾値, 点), ...], 大きい方が良いか, 満点)
# 素点の合計を100点満点に正規化してA〜Fに落とす。閾値は家庭用回線の実用的な感覚に合わせた独自基準で、
# DSLReports等の公式スコアとは一致しない(比較用の目安として使うこと)。
def _score_thresholds(value, thresholds, higher_is_better):
    if value is None:
        return None
    for limit, points in thresholds:
        if (value >= limit) if higher_is_better else (value <= limit):
            return points
    return 0


def grade_connection(result, contract_mbps=None):
    """診断結果から接続品質を採点しA〜Fのグレードを返す。測れなかった項目は除外して正規化する。
    contract_mbps 省略時は設定ストアの値(既定1000)を使う。"""
    if contract_mbps is None:
        contract_mbps = _setting("general.contract_mbps", 1000)
    def g(section, *keys):
        d = result.get(section) or {}
        for k in keys:
            if not isinstance(d, dict):
                return None
            d = d.get(k)
        return d if isinstance(d, (int, float)) else None

    down = g("throughput", "parallel6", "mbps") or g("throughput", "single", "mbps")
    up = g("upload", "parallel6", "mbps") or g("upload", "single", "mbps")
    rtt = g("latency", "1.1.1.1", "avg_ms")
    jitter = g("jitter", "jitter_ms")
    loaded_loss = g("bufferbloat", "loaded_latency", "loss_pct")
    bloat_pct = g("bufferbloat", "increase_pct")
    retrans = g("link_stats", "tcp_retransmit_pct")

    down_pct = (down / contract_mbps * 100) if down is not None else None
    up_pct = (up / contract_mbps * 100) if up is not None else None

    items = [
        ("下り速度(契約比)", down_pct, [(80, 25), (60, 21), (40, 16), (25, 11), (10, 5)], True, 25,
         f"{down:.0f} Mbps / 契約{contract_mbps} Mbps" if down is not None else None),
        ("上り速度(契約比)", up_pct, [(80, 20), (60, 17), (40, 13), (25, 9), (10, 4)], True, 20,
         f"{up:.0f} Mbps / 契約{contract_mbps} Mbps" if up is not None else None),
        ("遅延", rtt, [(10, 15), (20, 13), (40, 10), (70, 6), (120, 3)], False, 15,
         f"{rtt} ms" if rtt is not None else None),
        ("ジッター", jitter, [(2, 10), (5, 8), (10, 6), (20, 3)], False, 10,
         f"{jitter} ms" if jitter is not None else None),
        ("負荷時のパケット損失", loaded_loss, [(0, 15), (1, 12), (3, 8), (10, 4)], False, 15,
         f"{loaded_loss} %" if loaded_loss is not None else None),
        ("バッファブロート(負荷時の遅延増加)", bloat_pct, [(25, 10), (75, 8), (150, 5), (400, 2)], False, 10,
         f"+{bloat_pct} %" if bloat_pct is not None else None),
        ("TCP再送率", retrans, [(0.5, 5), (1, 4), (3, 2), (6, 1)], False, 5,
         f"{retrans} %" if retrans is not None else None),
    ]

    breakdown = []
    earned = possible = 0
    for name, value, thresholds, higher, maximum, display in items:
        points = _score_thresholds(value, thresholds, higher)
        if points is None:
            breakdown.append({"項目": name, "実測": "測定不可", "点": None, "満点": maximum})
            continue
        earned += points
        possible += maximum
        breakdown.append({"項目": name, "実測": display, "点": points, "満点": maximum})

    if possible == 0:
        return {"grade": "?", "score": None, "breakdown": breakdown,
                "comment": "採点できる項目がありませんでした"}

    score = round(earned / possible * 100, 1)
    for limit, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (35, "E")):
        if score >= limit:
            grade = letter
            break
    else:
        grade = "F"

    weakest = min((b for b in breakdown if b["点"] is not None),
                  key=lambda b: b["点"] / b["満点"], default=None)
    comment = f"最も足を引っ張っている項目: {weakest['項目']} ({weakest['実測']})" if weakest else ""

    return {"grade": grade, "score": score, "earned": earned, "possible": possible,
            "contract_mbps": contract_mbps, "breakdown": breakdown, "comment": comment}


def list_result_files():
    RESULTS_DIR.mkdir(exist_ok=True)
    files = [p for p in RESULTS_DIR.glob("*.json")
             if not p.name.startswith(NON_DIAGNOSTIC_PREFIXES)]
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)


def _get_nested(d, *keys, default="-"):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
    return default if d is None else d


def flatten_metrics(result):
    """before/after比較用に主要指標だけ平坦なdictへ変換する。
    古い結果ファイルには無い項目があるため、全て _get_nested のデフォルト("-")経由で取り出す。"""
    keys = ("latency", "throughput", "upload", "bufferbloat", "ipv6", "public_ip_info",
            "path_mtu", "jitter", "link_stats", "nat", "ip_version_compare",
            "time_sync", "quic", "dnsbl")
    (lat, thr, up, bb, ipv6, pub, mtu, jit, link, nat, ipcmp,
     tsync, quic, dnsbl) = (result.get(k) or {} for k in keys)
    grade = result.get("grade") or {}
    return {
        "ラベル": result.get("label", "-"),
        "計測日時": result.get("timestamp", "-"),
        "総合グレード": _get_nested(grade, "grade"),
        "総合スコア": _get_nested(grade, "score"),
        "公開IP": _get_nested(pub, "ip"),
        "ISP": _get_nested(pub, "org"),
        "IPv6グローバル": _get_nested(ipv6, "has_global_address"),
        "IPv6疎通": _get_nested(ipv6, "egress_reachable"),
        "経路MTU": _get_nested(mtu, "mtu"),
        "接続方式(MTUから推定)": _get_nested(mtu, "interpretation"),
        "NATタイプ": _get_nested(nat, "nat_type"),
        "遅延(GW)平均ms": _get_nested(lat, "gateway", "avg_ms"),
        "遅延(1.1.1.1)平均ms": _get_nested(lat, "1.1.1.1", "avg_ms"),
        "遅延(8.8.8.8)平均ms": _get_nested(lat, "8.8.8.8", "avg_ms"),
        "ジッターms": _get_nested(jit, "jitter_ms"),
        "MOS値": _get_nested(jit, "mos"),
        "通話品質": _get_nested(jit, "quality"),
        "下り単一Mbps": _get_nested(thr, "single", "mbps"),
        "下り6並列Mbps": _get_nested(thr, "parallel6", "mbps"),
        "上り単一Mbps": _get_nested(up, "single", "mbps"),
        "上り6並列Mbps": _get_nested(up, "parallel6", "mbps"),
        "TCP再送率%": _get_nested(link, "tcp_retransmit_pct"),
        "IPv4経由Mbps": _get_nested(ipcmp, "ipv4", "mbps"),
        "IPv6経由Mbps": _get_nested(ipcmp, "ipv6", "mbps"),
        "時刻ズレms": _get_nested(tsync, "offset_ms"),
        "QUIC利用可否": _get_nested(quic, "usable"),
        "DNSBL問題あり": _get_nested(dnsbl, "has_problem"),
        "バッファブロート アイドルms": _get_nested(bb, "idle_latency", "avg_ms"),
        "バッファブロート 負荷時ms": _get_nested(bb, "loaded_latency", "avg_ms"),
        "バッファブロート 負荷時損失%": _get_nested(bb, "loaded_latency", "loss_pct"),
        "簡易RPM近似値": _get_nested(bb, "rpm_approx"),
    }


if __name__ == "__main__":
    main()
