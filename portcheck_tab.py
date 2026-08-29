#!/usr/bin/env python3
"""ポート・UPnP・NAT詳細タブ。

自宅がIPv4 over IPv6 (SoftBank光 IPv6高速ハイブリッド等) の場合、
グローバルIPv4を複数利用者で共有し使えるポート範囲が制限されることがある。
このタブはその実態を「推測」ではなく実測で可視化する。

【重要な設計判断: 送信元ポートを固定してNATを測る】
既存の nd.detect_nat_type() は STUN サーバごとに新しい UDP ソケットを作る。
Windows はソケットごとに別のエフェメラルポートを割り当てる (実測: 58170/58171/58172 と連番) ため、
NAT が「送信元ポートをそのまま外部ポートに使う」タイプだと外部ポートも当然バラバラになり、
Symmetric NAT と誤判定される。実機で確認した誤判定例:

    nd.detect_nat_type() -> Symmetric NAT, external_ports [58170, 58171, 58172]
    送信元ポートを 30727 に固定して同じ3サーバに問い合わせ -> 全て 30727

同じ送信元ポートから複数の宛先に投げて外部ポートが一致するか、が NAT マッピングの正しい判定
(RFC 4787 の endpoint-independent mapping)。本モジュールは必ず送信元ポートを bind して測る。
"""
import concurrent.futures
import random
import re
import socket
import struct
import threading
import time
import tkinter as tk
import urllib.request
import xml.etree.ElementTree as ET
from tkinter import ttk

import psutil

import network_diag as nd

# ---------- 定数 ----------

STUN_MAGIC = 0x2112A442
SSDP_ADDR = ("239.255.255.250", 1900)

# 分布サンプリングとは別に、レンジ全域が使えるかを確かめる固定ポート群。
# IPv4 over IPv6 のポート共有 (MAP-E 等) だと、この中の多くが使えないか外部ポートが別の値に付け替わる。
SWEEP_PORTS = [1024, 2000, 5000, 8080, 10000, 15000, 20000, 25000, 30000,
               33333, 40000, 44444, 49152, 55000, 61000, 64000, 65000, 65500]

IGD_SEARCH_TARGETS = [
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")


# ---------- STUN (送信元ポート指定版) ----------

def stun_probe(server, port, src_port=None, timeout=3.0):
    """STUN Binding Request を投げ、(external_ip, external_port, local_port) を返す。失敗時 None。

    nd._stun_binding_request と違い src_port を bind できる。NAT のマッピング挙動を測るには
    送信元ポートを固定して宛先だけ変える必要があるため、この版が要る。
    """
    tid = bytes(random.getrandbits(8) for _ in range(12))
    packet = struct.pack("!HHI12s", 0x0001, 0, STUN_MAGIC, tid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        if src_port is not None:
            # SO_REUSEADDR は付けない。Windows では使用中ポートの横取りが起きうるので、
            # 使用中なら素直に OSError にして「使えなかった」として扱う。
            sock.bind(("", src_port))
        local_port = sock.getsockname()[1] if src_port is not None else None
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(2048)
        if local_port is None:
            local_port = sock.getsockname()[1]
    except OSError:
        return None
    finally:
        sock.close()
    mapped = parse_stun_response(data)
    return (mapped[0], mapped[1], local_port) if mapped else None


def parse_stun_response(data):
    """XOR-MAPPED-ADDRESS / MAPPED-ADDRESS を取り出す -> (ip, port) or None"""
    if len(data) < 20:
        return None
    msg_len = struct.unpack("!H", data[2:4])[0]
    pos, end = 20, min(20 + msg_len, len(data))
    while pos + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[pos:pos + 4])
        value = data[pos + 4:pos + 4 + attr_len]
        if attr_type == 0x0020 and len(value) >= 8:  # XOR-MAPPED-ADDRESS
            xport = struct.unpack("!H", value[2:4])[0] ^ (STUN_MAGIC >> 16)
            xip = struct.unpack("!I", value[4:8])[0] ^ STUN_MAGIC
            return socket.inet_ntoa(struct.pack("!I", xip)), xport
        if attr_type == 0x0001 and len(value) >= 8:  # MAPPED-ADDRESS (旧仕様)
            return socket.inet_ntoa(value[4:8]), struct.unpack("!H", value[2:4])[0]
        pos += 4 + attr_len + ((4 - attr_len % 4) % 4)
    return None


def free_local_port():
    """OS に空きUDPポートを1つ選ばせて番号だけ貰う。bind し直すまでの間に他が取る可能性は許容。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        return s.getsockname()[1]
    finally:
        s.close()


# ---------- 集計ロジック ----------

def summarize_ports(samples):
    """samples: [{"local_port": int, "ext_port": int}, ...] -> 分布の要約"""
    ports = sorted(s["ext_port"] for s in samples)
    if not ports:
        return {"n": 0}
    gaps = [b - a for a, b in zip(ports, ports[1:])]
    preserved = sum(1 for s in samples if s["local_port"] == s["ext_port"])
    return {
        "n": len(ports),
        "unique": len(set(ports)),
        "min": ports[0],
        "max": ports[-1],
        "span": ports[-1] - ports[0],
        "max_gap": max(gaps) if gaps else 0,
        "preserved": preserved,
        "preserved_pct": round(preserved / len(samples) * 100, 1),
        # 65536 の 1/16 (=4096) 以内に収まっていれば「狭い範囲に固まっている」とみなす
        "clustered": (ports[-1] - ports[0]) <= 4096,
    }


def describe_distribution(summary):
    """要約 -> (色タグ, 人間向けの一文)"""
    if not summary.get("n"):
        return "bad", "STUN応答が1件も得られず、外部ポートの分布を測定できませんでした。"
    if summary["preserved_pct"] >= 90:
        return ("good", f"外部ポートは送信元ポートと一致 ({summary['preserved']}/{summary['n']} 件)。"
                        "ルータがポート番号を付け替えていない=ポート保存型。"
                        "見かけ上ポートが散るのは送信元ポートが毎回違うためで、NATの制限ではありません。")
    if summary["clustered"]:
        return ("warn", f"外部ポートが {summary['min']}〜{summary['max']} (幅 {summary['span']}) の"
                        "狭い範囲に固まっています。IPv4 over IPv6 のポート分割割り当ての可能性があります。")
    return ("warn", f"外部ポートが {summary['min']}〜{summary['max']} に散らばり、"
                    f"送信元ポートとの一致は {summary['preserved']}/{summary['n']} 件。ルータがポートを付け替えています。")


def classify_mapping(trials):
    """trials: [{"src_port": int, "results": {server: ext_port|None}}, ...]
    同一送信元ポートから複数宛先に投げて外部ポートが一致するか -> NATマッピング種別。
    """
    usable = [t for t in trials if len([v for v in t["results"].values() if v]) >= 2]
    if not usable:
        return "unknown", "判定不能 (同一送信元ポートで2つ以上のSTUNサーバから応答を得られませんでした)"
    consistent = all(len({v for v in t["results"].values() if v}) == 1 for t in usable)
    if consistent:
        return ("good", "Endpoint-Independent Mapping (Cone NAT) — 同じ送信元ポートなら宛先が違っても"
                        "外部ポートが変わりません。P2P・オンラインゲームのNAT越えに有利です。")
    return ("bad", "Address/Port-Dependent Mapping (Symmetric NAT) — 宛先ごとに外部ポートが変わります。"
                   "P2P接続やゲームのマッチングで不利です。")


def summarize_sweep(rows):
    """rows: [{"src_port": int, "ext_port": int|None}, ...] -> レンジ全域が使えるかの判定"""
    replied = [r for r in rows if r["ext_port"] is not None]
    preserved = [r for r in replied if r["ext_port"] == r["src_port"]]
    n = len(rows)
    if not replied:
        return "bad", n, 0, 0, "掃引したポートから1件も応答がありません (UDPが塞がれている可能性)。"
    if len(replied) == n and len(preserved) == n:
        return ("good", n, len(replied), len(preserved),
                f"1024〜65500 に散らした {n} ポート全てが到達・ポート保存されました。"
                "使えるポート範囲の制限 (IPv4 over IPv6 のポート共有) は見られません。")
    blocked = [r["src_port"] for r in rows if r["ext_port"] is None]
    return ("warn", n, len(replied), len(preserved),
            f"{n} ポート中 {len(replied)} 応答 / {len(preserved)} ポート保存。"
            f"使えないポートがあります: {blocked[:12]}")


def parse_port_spec(spec):
    """'1-1024,8080,443' -> ソート済みポート番号リスト。不正なら ValueError。"""
    ports = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            lo, hi = int(lo), int(hi)
            if lo > hi:
                raise ValueError(f"範囲が逆です: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))
    if not ports:
        raise ValueError("ポートが指定されていません")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ポート番号は 1〜65535 の範囲で指定してください")
    return sorted(ports)


# ---------- SSDP / UPnP ----------

def parse_ssdp_response(text):
    """SSDP の HTTP 風応答をヘッダ辞書にする。キーは大文字化。"""
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().upper()
        if key:
            headers[key] = value.strip()
    return headers


def ssdp_search(st, timeout=3.0):
    """M-SEARCH を投げて (送信元IP, ヘッダ辞書, 生テキスト) のリストを返す。"""
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
           'MAN: "ssdp:discover"\r\n'
           "MX: 2\r\n"
           f"ST: {st}\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    found = []
    try:
        sock.sendto(msg, SSDP_ADDR)
        deadline = time.time() + timeout
        while time.time() < deadline:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                data, addr = sock.recvfrom(8192)
            except OSError:
                break
            text = data.decode("utf-8", "replace")
            found.append((addr[0], parse_ssdp_response(text), text))
    finally:
        sock.close()
    return found


def _strip_ns(tag):
    return tag.rpartition("}")[2]


def parse_device_xml(xml_text):
    """UPnP device description XML -> 機種情報とサービス一覧。"""
    root = ET.fromstring(xml_text)
    info = {"friendly_name": "", "manufacturer": "", "model_name": "", "model_number": "",
            "device_types": [], "services": []}
    simple = {"friendlyName": "friendly_name", "manufacturer": "manufacturer",
              "modelName": "model_name", "modelNumber": "model_number"}
    for el in root.iter():
        tag = _strip_ns(el.tag)
        key = simple.get(tag)
        if key and not info[key] and (el.text or "").strip():
            info[key] = el.text.strip()
        elif tag == "deviceType" and (el.text or "").strip():
            info["device_types"].append(el.text.strip())
    for svc in root.iter():
        if _strip_ns(svc.tag) != "service":
            continue
        entry = {_strip_ns(c.tag): (c.text or "").strip() for c in svc}
        if entry.get("serviceType"):
            info["services"].append({"type": entry["serviceType"],
                                     "control_url": entry.get("controlURL", "")})
    info["is_igd"] = any("InternetGatewayDevice" in d for d in info["device_types"])
    info["wan_services"] = [s for s in info["services"] if any(w in s["type"] for w in WAN_SERVICES)]
    return info


def fetch_url(url, timeout=5.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def parse_soap_external_ip(xml_text):
    """GetExternalIPAddress の SOAP 応答から IP を取り出す。"""
    m = re.search(r"<NewExternalIPAddress>\s*([^<\s]*)\s*</NewExternalIPAddress>", xml_text)
    return m.group(1) if m and m.group(1) else None


def soap_get_external_ip(control_url, service_type, timeout=5.0):
    body = ('<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:GetExternalIPAddress xmlns:u="{service_type}"/>'
            "</s:Body></s:Envelope>").encode()
    req = urllib.request.Request(control_url, data=body, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#GetExternalIPAddress"',
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return parse_soap_external_ip(resp.read().decode("utf-8", "replace"))


# ---------- NAT-PMP ----------

_NATPMP_RESULT = {0: "成功", 1: "非対応バージョン", 2: "拒否 (無効化されている)",
                  3: "ネットワーク障害", 4: "リソース不足", 5: "非対応opcode"}


def parse_natpmp_response(data):
    """RFC 6886 の公開アドレス応答 (12バイト) を解釈する -> dict or None"""
    if len(data) < 8:
        return None
    version, opcode = data[0], data[1]
    result, epoch = struct.unpack("!HI", data[2:8])
    info = {"version": version, "opcode": opcode, "result": result,
            "result_text": _NATPMP_RESULT.get(result, f"不明なコード {result}"),
            "epoch_s": epoch, "external_ip": None}
    if opcode == 128 and result == 0 and len(data) >= 12:
        info["external_ip"] = socket.inet_ntoa(data[8:12])
    return info


def natpmp_query(gateway, timeout=3.0):
    """UDP 5351 に NAT-PMP v0 の公開アドレス要求を投げる -> (dict|None, 生バイト|None, エラー文字列|None)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"\x00\x00", (gateway, 5351))
        data, _ = sock.recvfrom(64)
        return parse_natpmp_response(data), data, None
    except socket.timeout:
        return None, None, "無応答 (タイムアウト)"
    except OSError as e:
        return None, None, f"{type(e).__name__}: {e}"
    finally:
        sock.close()


# ---------- ローカル待ち受けポート ----------

def list_listening():
    """このPCの LISTEN 中TCP と バインド済みUDP を列挙する。

    netstat のパースはしない。日本語ロケールのラベル包含問題を避けられるうえ、
    psutil ならプロセスIDが直接取れる (実測: LISTEN 46件すべてPID解決済み)。
    """
    names = {}
    rows = []
    for c in psutil.net_connections(kind="inet"):
        is_udp = c.type == socket.SOCK_DGRAM
        if not is_udp and c.status != psutil.CONN_LISTEN:
            continue
        if not c.laddr:
            continue
        ip, port = c.laddr[0], c.laddr[1]
        if c.pid and c.pid not in names:
            try:
                names[c.pid] = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[c.pid] = "?"
        rows.append({
            "proto": "UDP" if is_udp else "TCP",
            "ip": ip, "port": port,
            "scope": listen_scope(ip),
            "pid": c.pid or 0,
            "process": names.get(c.pid, "?") if c.pid else "?",
        })
    rows.sort(key=lambda r: (r["port"], r["proto"], r["ip"]))
    return rows


def listen_scope(ip):
    """待ち受けアドレス -> 'local' (自PCのみ) / 'lan' (特定NICのみ) / 'any' (全インタフェース)"""
    if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
        return "local"
    if ip in ("0.0.0.0", "::", "*", ""):
        return "any"
    return "lan"


SCOPE_LABEL = {"local": "ローカルのみ", "lan": "特定アドレス", "any": "全インタフェース"}
SCOPE_TAG = {"local": "good", "lan": "warn", "any": "bad"}


# ---------- ポートスキャン ----------

def scan_ports(host, ports, timeout=0.5, workers=256, stop=None):
    """TCP connect スキャン。開いているポート番号のリストを返す。"""
    def probe(port):
        if stop is not None and stop.is_set():
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return port if s.connect_ex((host, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        return sorted(p for p in pool.map(probe, ports) if p is not None)


# ---------- タブ本体 ----------

SCAN_NOTICE = ("⚠  このスキャンは自分が管理している機器 (自宅のNAS・自作サーバ・ゲーム機など) の"
               "疎通確認のための機能です。他人の管理する機器に向けないでください。")

LISTEN_COLUMNS = [("proto", "種別", 60), ("port", "ポート", 70), ("ip", "待ち受けアドレス", 200),
                  ("scope", "公開範囲", 130), ("pid", "PID", 70), ("process", "プロセス", 240)]


class PortCheckTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self._stop = threading.Event()
        self._threads = []
        self._tinted = []          # (widget, theme_key) テーマ切替で塗り直す ttk.Label
        self.port_samples = []     # 分布サンプリング結果
        self.sweep_rows = []       # レンジ掃引結果

        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True, padx=4, pady=(8, 4))
        self._build_nat(ttk.Frame(nb, padding=8), nb)
        self._build_upnp(ttk.Frame(nb, padding=8), nb)
        self._build_listen(ttk.Frame(nb, padding=8), nb)
        self._build_scan(ttk.Frame(nb, padding=8), nb)
        self.on_theme_changed()

    # ---- 共通部品 ----

    def _tint(self, widget, key):
        self._tinted.append((widget, key))
        return widget

    def _spawn(self, fn):
        th = threading.Thread(target=fn, daemon=True)
        th.start()
        self._threads.append(th)

    def _ui(self, fn, *a):
        """ワーカースレッドからのUI更新は必ずここを通す。"""
        if not self._stop.is_set():
            self.ctx.root.after(0, lambda: fn(*a))

    def _set(self, label, text, key="muted"):
        label.config(text=text, foreground=self.ctx.theme[key])
        for i, (w, _) in enumerate(self._tinted):
            if w is label:
                self._tinted[i] = (label, key)
                break
        else:
            self._tinted.append((label, key))

    @staticmethod
    def _text_widget(parent, height):
        t = tk.Text(parent, height=height, wrap="none", relief="flat", borderwidth=0,
                    font=("Consolas", 9))
        t.configure(state="disabled")
        return t

    def _write(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ---- 1. 外部ポート挙動 ----

    def _build_nat(self, f, nb):
        nb.add(f, text="外部ポート挙動")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="サンプル数").pack(side="left", padx=(0, 6))
        self.samples_var = tk.IntVar(value=30)
        ttk.Spinbox(top, from_=10, to=100, increment=5, textvariable=self.samples_var,
                    width=6).pack(side="left", padx=(0, 12))
        self.nat_btn = ttk.Button(top, text="▶  測定", style="Accent.TButton", command=self.run_nat)
        self.nat_btn.pack(side="left")

        self.nat_status = self._tint(ttk.Label(f, text="未測定"), "muted")
        self.nat_status.pack(fill="x", pady=(8, 4))

        self.canvas = tk.Canvas(f, height=120, highlightthickness=0)
        self.canvas.pack(fill="x", pady=(4, 8))
        self.canvas.bind("<Configure>", lambda e: self._draw_ports())

        self.verdict_map = self._tint(ttk.Label(f, text="", wraplength=1050, justify="left"), "fg")
        self.verdict_map.pack(fill="x", pady=2)
        self.verdict_dist = self._tint(ttk.Label(f, text="", wraplength=1050, justify="left"), "fg")
        self.verdict_dist.pack(fill="x", pady=2)
        self.verdict_sweep = self._tint(ttk.Label(f, text="", wraplength=1050, justify="left"), "fg")
        self.verdict_sweep.pack(fill="x", pady=2)

        self.nat_log = self._text_widget(f, 12)
        self.nat_log.pack(fill="both", expand=True, pady=(8, 0))

    def run_nat(self):
        self.nat_btn.config(state="disabled")
        self._spawn(self._nat_worker)

    def _nat_worker(self):
        lines = []
        servers = nd.STUN_SERVERS

        # フェーズ1: OS任せの送信元ポートで分布を集める
        n = self.samples_var.get()
        samples = []
        for i in range(n):
            if self._stop.is_set():
                return
            self._ui(self._set, self.nat_status, f"分布サンプリング {i + 1}/{n} ...", "muted")
            srv = servers[i % len(servers)]
            r = stun_probe(srv[0], srv[1])
            if r:
                samples.append({"server": srv[0], "ext_ip": r[0], "ext_port": r[1], "local_port": r[2]})
                lines.append(f"[分布] {srv[0]:<22} 送信元 {r[2]:<6} -> 外部 {r[0]}:{r[1]}"
                             f"  {'一致' if r[1] == r[2] else '★付け替え'}")
            else:
                lines.append(f"[分布] {srv[0]:<22} 無応答")
        self.port_samples = samples

        # フェーズ2: 送信元ポートを固定して宛先を変える = マッピング挙動の正しい測り方
        trials = []
        for k in range(3):
            if self._stop.is_set():
                return
            self._ui(self._set, self.nat_status, f"マッピング判定 {k + 1}/3 ...", "muted")
            src = free_local_port()
            results = {}
            for host, port in servers:
                r = stun_probe(host, port, src_port=src)
                results[host] = r[1] if r else None
            trials.append({"src_port": src, "results": results})
            lines.append(f"[マッピング] 送信元 {src} 固定 -> " +
                         ", ".join(f"{h}:{v if v else '無応答'}" for h, v in results.items()) +
                         ("   ★全一致=Cone" if len({v for v in results.values() if v}) == 1 else ""))

        # フェーズ3: レンジ全域の掃引
        sweep = []
        for i, sp in enumerate(SWEEP_PORTS):
            if self._stop.is_set():
                return
            self._ui(self._set, self.nat_status, f"レンジ掃引 {i + 1}/{len(SWEEP_PORTS)} ...", "muted")
            r = stun_probe(servers[0][0], servers[0][1], src_port=sp, timeout=2.0)
            sweep.append({"src_port": sp, "ext_port": r[1] if r else None})
            lines.append(f"[掃引] 送信元 {sp:<6} -> " +
                         ("無応答/bind不可" if not r else
                          f"外部 {r[1]:<6} {'保存' if r[1] == sp else '★付け替え'}"))
        self.sweep_rows = sweep

        summary = summarize_ports(samples)
        map_key, map_text = classify_mapping(trials)
        dist_key, dist_text = describe_distribution(summary)
        sw_key, sw_n, sw_reply, sw_pres, sw_text = summarize_sweep(sweep)
        ext_ips = sorted({s["ext_ip"] for s in samples})

        def finish():
            self._set(self.nat_status,
                      f"完了  外部IP {', '.join(ext_ips) or '不明'}  /  "
                      f"応答 {summary.get('n', 0)}/{n}  /  掃引 {sw_reply}/{sw_n} 応答・{sw_pres} 保存",
                      "good" if summary.get("n") else "bad")
            self._set(self.verdict_map, f"■ NATマッピング: {map_text}", map_key)
            self._set(self.verdict_dist, f"■ 外部ポート分布: {dist_text}", dist_key)
            self._set(self.verdict_sweep, f"■ 使えるポート範囲: {sw_text}", sw_key)
            self._write(self.nat_log, "\n".join(lines))
            self._draw_ports()
            self.nat_btn.config(state="normal")

        self._ui(finish)

    def _draw_ports(self):
        """0〜65535 の軸上に、観測した外部ポートを縦線で打つ。固まるか散るかが一目で分かる。"""
        c = self.canvas
        t = self.ctx.theme
        c.delete("all")
        w = c.winfo_width() or 800
        h = 120
        left, right, base = 50, w - 20, 78
        c.create_rectangle(0, 0, w, h, fill=t["graph_bg"], outline="")
        if right <= left:
            return

        def x_of(port):
            return left + (right - left) * port / 65535

        for tick in (0, 16384, 32768, 49152, 65535):
            x = x_of(tick)
            c.create_line(x, 20, x, base, fill=t["graph_grid"])
            c.create_text(x, base + 12, text=str(tick), fill=t["muted"],
                          font=(self.ctx.font, 8), anchor="n")
        c.create_line(left, base, right, base, fill=t["graph_grid"])

        if not self.port_samples and not self.sweep_rows:
            c.create_text((left + right) / 2, 46, text="「測定」を押すと外部ポートの分布を表示します",
                          fill=t["muted"], font=(self.ctx.font, 9))
            return

        for row in self.sweep_rows:
            if row["ext_port"] is not None:
                x = x_of(row["ext_port"])
                c.create_line(x, 52, x, base, fill=t["muted"])
        for s in self.port_samples:
            x = x_of(s["ext_port"])
            c.create_line(x, 24, x, base, fill=t["good"] if s["ext_port"] == s["local_port"] else t["bad"])

        c.create_text(left, 8, text="上段: 分布サンプリング (緑=送信元と一致 / 赤=付け替え)   "
                                    "下段: レンジ掃引で到達したポート",
                      fill=t["muted"], font=(self.ctx.font, 8), anchor="nw")
        summary = summarize_ports(self.port_samples)
        if summary.get("n"):
            c.create_text(right, 8, text=f"最小 {summary['min']} / 最大 {summary['max']} / 幅 {summary['span']}",
                          fill=t["fg"], font=(self.ctx.font, 9), anchor="ne")

    # ---- 2. UPnP / NAT-PMP ----

    def _build_upnp(self, f, nb):
        nb.add(f, text="UPnP / NAT-PMP")
        top = ttk.Frame(f)
        top.pack(fill="x")
        self.upnp_btn = ttk.Button(top, text="▶  探索", style="Accent.TButton", command=self.run_upnp)
        self.upnp_btn.pack(side="left")
        self.upnp_status = self._tint(ttk.Label(f, text="未探索"), "muted")
        self.upnp_status.pack(fill="x", pady=(8, 4))
        self.upnp_verdict = self._tint(ttk.Label(f, text="", wraplength=1050, justify="left"), "fg")
        self.upnp_verdict.pack(fill="x", pady=2)
        self.upnp_log = self._text_widget(f, 24)
        self.upnp_log.pack(fill="both", expand=True, pady=(8, 0))

    def run_upnp(self):
        self.upnp_btn.config(state="disabled")
        self._spawn(self._upnp_worker)

    def _upnp_worker(self):
        out = []
        gw = nd.get_default_gateway()
        out.append(f"デフォルトゲートウェイ: {gw or '不明'}")

        # --- SSDP ---
        self._ui(self._set, self.upnp_status, "SSDP で UPnP デバイスを探索中 ...", "muted")
        devices = {}   # location -> {"ip":..., "sts": set(), "server":...}
        igd_hits = {}
        for st in IGD_SEARCH_TARGETS:
            if self._stop.is_set():
                return
            hits = ssdp_search(st, timeout=3.0)
            igd_hits[st] = len(hits)
            for ip, headers, raw in hits:
                loc = headers.get("LOCATION") or headers.get("AL") or ""
                if not loc:
                    continue
                d = devices.setdefault(loc, {"ip": ip, "sts": set(), "server": headers.get("SERVER", ""),
                                             "raw": raw})
                d["sts"].add(headers.get("ST", ""))

        out.append("\n--- M-SEARCH 応答数 ---")
        for st, cnt in igd_hits.items():
            out.append(f"  {cnt:>3} 件  ST: {st}")

        out.append(f"\n--- 発見したデバイス {len(devices)} 件 ---")
        igd_found = []
        for loc, d in devices.items():
            out.append(f"\n[{d['ip']}]  {loc}")
            out.append(f"  SERVER: {d['server']}")
            for st in sorted(d["sts"]):
                out.append(f"  ST: {st}")
            self._ui(self._set, self.upnp_status, f"description XML 取得中: {loc}", "muted")
            try:
                xml_text = fetch_url(loc, timeout=5.0)
            except Exception as e:                       # noqa: BLE001 - 到達不能・不正XML等をまとめて報告
                out.append(f"  → XML取得に失敗: {type(e).__name__}: {e}")
                out.append("     (LOCATION は広告されているが、そのポートに実際には繋がらない)")
                continue
            try:
                info = parse_device_xml(xml_text)
            except ET.ParseError as e:
                out.append(f"  → XMLパースに失敗: {e}")
                continue
            out.append(f"  機種名   : {info['friendly_name'] or '-'}")
            out.append(f"  メーカー : {info['manufacturer'] or '-'}")
            out.append(f"  モデル   : {info['model_name'] or '-'} {info['model_number']}".rstrip())
            for dt in info["device_types"]:
                out.append(f"  deviceType : {dt}")
            for svc in info["services"]:
                out.append(f"  service    : {svc['type']}")
            if info["wan_services"]:
                igd_found.append((loc, info))

        # --- IGD が居れば GetExternalIPAddress を呼ぶ ---
        upnp_external_ip = None
        for loc, info in igd_found:
            base = re.match(r"(https?://[^/]+)", loc).group(1)
            for svc in info["wan_services"]:
                url = svc["control_url"]
                if not url.startswith("http"):
                    url = base + ("" if url.startswith("/") else "/") + url
                self._ui(self._set, self.upnp_status, f"SOAP GetExternalIPAddress: {url}", "muted")
                try:
                    ip = soap_get_external_ip(url, svc["type"])
                    out.append(f"\n  SOAP GetExternalIPAddress ({svc['type']}) -> {ip or '空の応答'}")
                    upnp_external_ip = upnp_external_ip or ip
                except Exception as e:                   # noqa: BLE001
                    out.append(f"\n  SOAP GetExternalIPAddress 失敗: {type(e).__name__}: {e}")

        # --- NAT-PMP ---
        out.append("\n--- NAT-PMP (UDP 5351) ---")
        pmp = None
        if gw:
            self._ui(self._set, self.upnp_status, f"NAT-PMP を {gw}:5351 に問い合わせ中 ...", "muted")
            pmp, raw, err = natpmp_query(gw, timeout=3.0)
            if pmp:
                out.append(f"  応答あり raw={raw.hex()}")
                out.append(f"  version={pmp['version']} opcode={pmp['opcode']} "
                           f"result={pmp['result']} ({pmp['result_text']})")
                out.append(f"  外部IP: {pmp['external_ip'] or '-'}")
            else:
                out.append(f"  {err} → NAT-PMP は無効、またはこのルータは非対応")
        else:
            out.append("  ゲートウェイ不明のためスキップ")

        verdict_key, verdict = self._upnp_verdict(igd_found, upnp_external_ip, pmp)

        def finish():
            self._set(self.upnp_status,
                      f"完了  デバイス {len(devices)} 件 / IGD {len(igd_found)} 件 / "
                      f"NAT-PMP {'応答あり' if pmp else '無応答'}",
                      "good" if igd_found or pmp else "warn")
            self._set(self.upnp_verdict, verdict, verdict_key)
            self._write(self.upnp_log, "\n".join(out))
            self.upnp_btn.config(state="normal")

        self._ui(finish)

    @staticmethod
    def _upnp_verdict(igd_found, upnp_ip, pmp):
        if igd_found:
            got = f" 外部IPも取得できました ({upnp_ip})。" if upnp_ip else ""
            return ("good", f"■ UPnP IGD が有効です。{got}"
                            "ゲームやP2Pアプリが自動でポート開放でき、NAT越えの問題は起きにくい状態です。")
        if pmp and pmp.get("result") == 0:
            return ("good", f"■ NAT-PMP が有効です (外部IP {pmp.get('external_ip') or '不明'})。"
                            "対応アプリは自動でポート開放できます。")
        return ("bad", "■ UPnP IGD も NAT-PMP も利用できません。アプリからの自動ポート開放は不可能です。"
                       "着信を伴う用途 (ゲームのホスト・P2P) は、ルータの管理画面で手動ポートマッピングを"
                       "設定するしかありません。")

    # ---- 3. ローカル待ち受けポート ----

    def _build_listen(self, f, nb):
        nb.add(f, text="待ち受けポート")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Button(top, text="↺  更新", style="Accent.TButton", command=self.run_listen).pack(side="left")
        self.udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="UDPも表示", variable=self.udp_var,
                        command=self.run_listen).pack(side="left", padx=12)
        self.listen_status = self._tint(ttk.Label(f, text="未取得"), "muted")
        self.listen_status.pack(fill="x", pady=(8, 4))
        legend = self._tint(ttk.Label(f, text="色: 赤=全インタフェース待ち受け(LAN/外部から到達しうる)  "
                                              "黄=特定アドレスのみ  緑=127.0.0.1 (このPC内のみ)"), "muted")
        legend.pack(fill="x", pady=(0, 4))
        self.listen_tree = ttk.Treeview(f, columns=[c[0] for c in LISTEN_COLUMNS],
                                        show="headings", height=20)
        for key, head, width in LISTEN_COLUMNS:
            self.listen_tree.heading(key, text=head)
            self.listen_tree.column(key, width=width,
                                    anchor="e" if key in ("port", "pid") else "w",
                                    stretch=key == "process")
        self.listen_tree.pack(fill="both", expand=True)

    def run_listen(self):
        self._spawn(self._listen_worker)

    def _listen_worker(self):
        try:
            rows = list_listening()
        except Exception as e:                            # noqa: BLE001
            self._ui(self._set, self.listen_status, f"取得に失敗: {type(e).__name__}: {e}", "bad")
            return
        if not self.udp_var.get():
            rows = [r for r in rows if r["proto"] == "TCP"]

        def finish():
            self.listen_tree.delete(*self.listen_tree.get_children())
            for r in rows:
                self.listen_tree.insert("", "end", values=(
                    r["proto"], r["port"], r["ip"], SCOPE_LABEL[r["scope"]],
                    r["pid"] or "", r["process"]), tags=(SCOPE_TAG[r["scope"]],))
            n_any = sum(1 for r in rows if r["scope"] == "any")
            self._set(self.listen_status,
                      f"{len(rows)} 件  (うち全インタフェース待ち受け {n_any} 件)", "muted")

        self._ui(finish)

    # ---- 4. ポートスキャン ----

    def _build_scan(self, f, nb):
        nb.add(f, text="ポートスキャン")
        notice = self._tint(ttk.Label(f, text=SCAN_NOTICE, wraplength=1050, justify="left"), "warn")
        notice.pack(fill="x", pady=(0, 8))
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="ホスト").pack(side="left", padx=(0, 6))
        self.scan_host = tk.StringVar(value="")   # 既定値なし。対象は必ずユーザーが指定する
        ttk.Entry(top, textvariable=self.scan_host, width=24).pack(side="left", padx=(0, 12))
        ttk.Label(top, text="ポート").pack(side="left", padx=(0, 6))
        self.scan_ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(top, textvariable=self.scan_ports_var, width=24).pack(side="left", padx=(0, 12))
        ttk.Label(top, text="タイムアウト(秒)").pack(side="left", padx=(0, 6))
        self.scan_timeout = tk.DoubleVar(value=0.5)
        ttk.Spinbox(top, from_=0.1, to=5.0, increment=0.1, textvariable=self.scan_timeout,
                    width=6).pack(side="left", padx=(0, 12))
        self.scan_btn = ttk.Button(top, text="▶  スキャン", style="Accent.TButton", command=self.run_scan)
        self.scan_btn.pack(side="left")

        hint = self._tint(ttk.Label(f, text="例: 1-1024 / 22,80,443,8080 / 8000-8100  "
                                            "(自分のNASやサーバに向けて、そのポートが開いているか確認できます)"),
                          "muted")
        hint.pack(fill="x", pady=(6, 0))
        self.scan_status = self._tint(ttk.Label(f, text="待機中"), "muted")
        self.scan_status.pack(fill="x", pady=(8, 4))
        self.scan_log = self._text_widget(f, 20)
        self.scan_log.pack(fill="both", expand=True, pady=(4, 0))

    def run_scan(self):
        host = self.scan_host.get().strip()
        if not host:
            self._set(self.scan_status, "対象ホストを入力してください (自分の管理下の機器に限ります)", "warn")
            return
        try:
            ports = parse_port_spec(self.scan_ports_var.get())
        except ValueError as e:
            self._set(self.scan_status, f"ポート指定が不正です: {e}", "bad")
            return
        self.scan_btn.config(state="disabled")
        self._spawn(lambda: self._scan_worker(host, ports))

    def _scan_worker(self, host, ports):
        try:
            ip = socket.gethostbyname(host)
        except OSError as e:
            self._ui(self._set, self.scan_status, f"名前解決に失敗: {host} ({e})", "bad")
            self._ui(lambda: self.scan_btn.config(state="normal"))
            return
        self._ui(self._set, self.scan_status, f"{host} ({ip}) の {len(ports)} ポートをスキャン中 ...", "muted")
        t0 = time.perf_counter()
        found = scan_ports(ip, ports, timeout=self.scan_timeout.get(), stop=self._stop)
        elapsed = time.perf_counter() - t0

        lines = [f"対象: {host} ({ip})   {len(ports)} ポート   {elapsed:.1f} 秒", ""]
        if found:
            lines.append(f"開いているポート ({len(found)} 件):")
            lines += [f"  {p:<6} {_wellknown(p)}" for p in found]
        else:
            lines.append("開いているポートはありませんでした。")

        def finish():
            self._set(self.scan_status,
                      f"完了  {len(found)} / {len(ports)} ポートが開いています  ({elapsed:.1f} 秒)",
                      "good" if found else "muted")
            self._write(self.scan_log, "\n".join(lines))
            self.scan_btn.config(state="normal")

        self._ui(finish)

    # ---- テーマ / 終了 ----

    def on_theme_changed(self):
        t = self.ctx.theme
        for widget, key in self._tinted:
            widget.config(foreground=t[key])
        for tag in ("good", "warn", "bad"):
            self.listen_tree.tag_configure(tag, foreground=t[tag])
        # sv_ttk が Treeview の style map に -foreground を入れており、そのままだとタグ色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる (pathmon_tab.py と同じ対処)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        for txt in (self.nat_log, self.upnp_log, self.scan_log):
            txt.config(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"],
                       selectbackground=t["graph_grid"])
        self.canvas.config(bg=t["graph_bg"])
        self._draw_ports()

    def on_close(self):
        self._stop.set()
        for th in self._threads:
            th.join(timeout=2)


_WELLKNOWN = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
              139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 548: "AFP", 587: "SMTP",
              631: "IPP", 993: "IMAPS", 995: "POP3S", 1900: "SSDP", 3389: "RDP", 5000: "UPnP/HTTP",
              5001: "Synology DSM", 5357: "WSD", 5432: "PostgreSQL", 8006: "Proxmox",
              8080: "HTTP-alt", 8443: "HTTPS-alt", 9000: "HTTP-alt", 32400: "Plex"}


def _wellknown(port):
    return _WELLKNOWN.get(port, "")


# ---------- 自己テスト ----------

def _selftest():
    # --- SSDP 応答のパース (実機の光BBユニットが返した生データ) ---
    real = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1801\r\nDATE: Sun, 23 Aug 2026 21:14:27 GMT\r\n"
            "EXT:\r\nLOCATION: http://192.168.3.1:49152/wps_device.xml\r\n"
            "SERVER: Unspecified, UPnP/1.0, Unspecified\r\n"
            "ST: urn:schemas-wifialliance-org:device:WFADevice:1\r\n"
            "USN: uuid:7145f4c1-44bb-598f-af37-32b3f5ccee23::"
            "urn:schemas-wifialliance-org:device:WFADevice:1\r\n\r\n")
    h = parse_ssdp_response(real)
    assert h["LOCATION"] == "http://192.168.3.1:49152/wps_device.xml", h
    assert h["ST"] == "urn:schemas-wifialliance-org:device:WFADevice:1", h
    assert h["EXT"] == "", h                      # 値なしヘッダも落とさない
    assert h["SERVER"] == "Unspecified, UPnP/1.0, Unspecified", h
    # LOCATION の値に ':' が複数あっても最初の1個だけで分割していること
    assert parse_ssdp_response("HTTP/1.1 200 OK\nLOCATION: http://a:1/b\n")["LOCATION"] == "http://a:1/b"
    # Chromecast のように小文字ヘッダで返す実装もある (実機で観測済み)
    assert parse_ssdp_response("HTTP/1.1 200 OK\r\nLocation: http://192.168.3.8:12346/description.xml\r\n"
                               )["LOCATION"] == "http://192.168.3.8:12346/description.xml"

    # --- device description XML のパース ---
    igd_xml = """<?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0"><device>
      <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
      <friendlyName>Test Router</friendlyName><manufacturer>ACME</manufacturer>
      <modelName>RT-1000</modelName><modelNumber>v2</modelNumber>
      <deviceList><device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <serviceList><service>
          <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
          <controlURL>/ctl/IPConn</controlURL>
        </service></serviceList>
      </device></deviceList>
    </device></root>"""
    info = parse_device_xml(igd_xml)
    assert info["is_igd"] and info["friendly_name"] == "Test Router", info
    assert info["manufacturer"] == "ACME" and info["model_name"] == "RT-1000", info
    assert len(info["wan_services"]) == 1, info
    assert info["wan_services"][0]["control_url"] == "/ctl/IPConn", info
    # 名前空間なしのXMLでも同じく読めること
    assert parse_device_xml("<root><device><friendlyName>X</friendlyName>"
                            "<deviceType>urn:x:device:Foo:1</deviceType></device></root>"
                            )["friendly_name"] == "X"
    # WPS専用デバイス (実機の光BBユニット相当) は IGD ではない
    wps = parse_device_xml("<root xmlns='urn:schemas-upnp-org:device-1-0'><device>"
                           "<deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>"
                           "<friendlyName>WFADevice</friendlyName><serviceList><service>"
                           "<serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType>"
                           "<controlURL>/wps</controlURL></service></serviceList>"
                           "</device></root>")
    assert not wps["is_igd"] and not wps["wan_services"], wps

    assert parse_soap_external_ip(
        "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>"
        "<NewExternalIPAddress>126.1.32.112</NewExternalIPAddress>"
        "</u:GetExternalIPAddressResponse></s:Body></s:Envelope>") == "126.1.32.112"
    assert parse_soap_external_ip("<NewExternalIPAddress></NewExternalIPAddress>") is None
    assert parse_soap_external_ip("<s:Fault/>") is None

    # --- NAT-PMP 応答のパース ---
    ok = b"\x00\x80\x00\x00" + struct.pack("!I", 12345) + socket.inet_aton("126.1.32.112")
    p = parse_natpmp_response(ok)
    assert p["opcode"] == 128 and p["result"] == 0 and p["external_ip"] == "126.1.32.112", p
    assert p["epoch_s"] == 12345, p
    refused = parse_natpmp_response(b"\x00\x80\x00\x02" + struct.pack("!I", 1))
    assert refused["external_ip"] is None and "拒否" in refused["result_text"], refused
    assert parse_natpmp_response(b"\x00\x80\x00\x63" + b"\x00" * 4)["result_text"].startswith("不明"), "unknown code"
    assert parse_natpmp_response(b"\x00\x80") is None            # 短すぎる応答
    assert parse_natpmp_response(b"") is None

    # --- STUN 応答のパース ---
    xport = 38253 ^ (STUN_MAGIC >> 16)
    xip = int.from_bytes(socket.inet_aton("126.1.32.112"), "big") ^ STUN_MAGIC
    attr = struct.pack("!HHBBH", 0x0020, 8, 0, 0x01, xport) + struct.pack("!I", xip)
    msg = struct.pack("!HHI12s", 0x0101, len(attr), STUN_MAGIC, b"\x00" * 12) + attr
    assert parse_stun_response(msg) == ("126.1.32.112", 38253), parse_stun_response(msg)
    assert parse_stun_response(b"\x00" * 8) is None

    # --- ポート範囲の集計 ---
    # 実機で観測した「送信元ポートがそのまま外部ポートになる」パターン
    preserved = [{"local_port": p, "ext_port": p} for p in range(63768, 63798)]
    s = summarize_ports(preserved)
    assert s["n"] == 30 and s["unique"] == 30, s
    assert (s["min"], s["max"], s["span"]) == (63768, 63797, 29), s
    assert s["preserved"] == 30 and s["preserved_pct"] == 100.0, s
    assert s["clustered"] and s["max_gap"] == 1, s
    assert describe_distribution(s)[0] == "good"
    # 付け替えられて広く散るパターン
    scattered = [{"local_port": 50000 + i, "ext_port": p}
                 for i, p in enumerate([1234, 20000, 41000, 60000])]
    s2 = summarize_ports(scattered)
    assert s2["preserved"] == 0 and not s2["clustered"] and s2["span"] == 58766, s2
    assert describe_distribution(s2)[0] == "warn"
    # 付け替えられて狭い範囲に固まるパターン (MAP-E 等のポート分割割り当ての疑い)
    s3 = summarize_ports([{"local_port": 50000 + i, "ext_port": 64192 + i} for i in range(16)])
    assert s3["clustered"] and s3["preserved"] == 0, s3
    assert describe_distribution(s3)[0] == "warn" and "固まって" in describe_distribution(s3)[1]
    assert summarize_ports([]) == {"n": 0}
    assert describe_distribution({"n": 0})[0] == "bad"

    # --- マッピング判定 ---
    srv = ["a", "b", "c"]
    eim = [{"src_port": 30727, "results": dict.fromkeys(srv, 30727)}]
    assert classify_mapping(eim)[0] == "good", classify_mapping(eim)
    sym = [{"src_port": 30727, "results": {"a": 58170, "b": 58171, "c": 58172}}]
    assert classify_mapping(sym)[0] == "bad", classify_mapping(sym)
    # 応答が1件しかない試行は判定に使わない
    assert classify_mapping([{"src_port": 1, "results": {"a": 100, "b": None, "c": None}}])[0] == "unknown"
    assert classify_mapping([])[0] == "unknown"
    # 一部無応答でも、応答した2件が一致していれば EIM と判定できる
    assert classify_mapping([{"src_port": 1, "results": {"a": 555, "b": 555, "c": None}}])[0] == "good"
    # 複数試行のうち1つでも食い違えば symmetric
    assert classify_mapping(eim + sym)[0] == "bad"

    # --- レンジ掃引の集計 ---
    all_ok = [{"src_port": p, "ext_port": p} for p in SWEEP_PORTS]
    key, n, reply, pres, _ = summarize_sweep(all_ok)
    assert key == "good" and n == reply == pres == len(SWEEP_PORTS), (key, n, reply, pres)
    partial = [{"src_port": p, "ext_port": (p if i % 2 else None)} for i, p in enumerate(SWEEP_PORTS)]
    assert summarize_sweep(partial)[0] == "warn"
    assert summarize_sweep([{"src_port": p, "ext_port": None} for p in SWEEP_PORTS])[0] == "bad"

    # --- ポート指定のパース ---
    assert parse_port_spec("80") == [80]
    assert parse_port_spec("80,443,80") == [80, 443]           # 重複は畳む
    assert parse_port_spec("20-22") == [20, 21, 22]
    assert parse_port_spec(" 22 , 80-82 ") == [22, 80, 81, 82]
    assert parse_port_spec("65535") == [65535]
    for bad in ("", "  ", "0-10", "1-70000", "70000", "100-50", "abc", "-", "80-"):
        try:
            parse_port_spec(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"不正な指定が通ってしまった: {bad!r}")

    # --- 待ち受けアドレスの分類 ---
    assert listen_scope("127.0.0.1") == "local" and listen_scope("::1") == "local"
    assert listen_scope("127.0.0.53") == "local"
    assert listen_scope("0.0.0.0") == "any" and listen_scope("::") == "any"
    assert listen_scope("192.168.3.5") == "lan" and listen_scope("fe80::1") == "lan"
    assert set(SCOPE_TAG) == set(SCOPE_LABEL) == {"local", "lan", "any"}

    assert _wellknown(443) == "HTTPS" and _wellknown(12345) == ""

    print("portcheck selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1150x700")
    root.title("ポート・UPnP・NAT詳細")
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
    tab = PortCheckTab(frame, ctx)
    root.after(300, tab.run_listen)
    if "--auto" in sys.argv:
        root.after(500, tab.run_upnp)
        root.after(1000, tab.run_nat)
        root.after(120000, lambda: (tab.on_close(), root.destroy()))
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
