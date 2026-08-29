#!/usr/bin/env python3
"""DNS詳細監査タブ。DNSの「速さ」ではなく「応答の正しさ・安全性」を見る。

  1. NXDOMAINハイジャック検出 (存在しない名前にIPを返してこないか)
  2. 応答の一致検証 (リゾルバ間でAレコードの組織が食い違わないか)
  3. DNSSEC検証の有無 (DOビット付き問い合わせにADフラグが立つか)
  4. DoH(443) / DoT(853) の到達性 (ルーターが暗号化DNSを塞いでいないか)
  5. 逆引き(PTR)

DNSクエリは network_diag.dns_query_time() と同じ流儀で struct から自前で組む
(dnspython等は追加しない)。応答時間しか見ない元実装に対し、こちらは
RCODE / ADフラグ / EDNS0のDOビット / レコードの中身まで扱う必要があるため
ビルダとパーサを本モジュールに持つ。

実測で確定した仕様 (2026-08 / SoftBank光 光BBユニット環境):
- ADフラグは「DOビットを立てた問い合わせ」にしか立たない。DOなしだと
  1.1.1.1/8.8.8.8 でも AD=False が返るため、DOビットは必須。
- 1.1.1.1 の443/853はPythonの既定証明書ストアでは中間CAを辿れず検証に失敗する
  (Windowsのオンデマンド取得に依存しているため)。これは「ポートが塞がれている」
  のとは別物なので、検証なしで再接続して到達性そのものは切り分ける。
- 9.9.9.9 のDoHはHTTP/2必須。http.clientはHTTP/1.1のみなので505が返る。
  505が返ること自体が「443に到達できている」証拠なので、そう扱う。
"""
import base64
import http.client
import json
import random
import socket
import ssl
import struct
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import network_diag as nd

# ---------- 監査対象 ----------

PUBLIC_RESOLVERS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9")]
CONSISTENCY_DOMAINS = ["google.com", "cloudflare.com", "www.softbank.jp", "www.yahoo.co.jp"]
DNSSEC_SIGNED = ["cloudflare.com", "internetsociety.org"]
DNSSEC_BROKEN = "dnssec-failed.org"  # 意図的に署名が壊れているテスト用ドメイン
# DoH/DoT はSNI用のホスト名が要る (IPだけだと証明書のホスト名検証が通らない)
ENCRYPTED_HOSTS = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google"), ("9.9.9.9", "dns.quad9.net")]

QTYPE_A = 1
QTYPE_PTR = 12
EDNS_DO = 0x8000       # OPTレコードのTTLフィールド上位に置くDNSSEC OKビット
EDNS_UDP_SIZE = 4096
OPT_TYPE = 41

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH"}


def rcode_name(code):
    return RCODE_NAMES.get(code, f"RCODE={code}")


# ---------- DNSパケット (network_diag.dns_query_time と同じ struct 流儀) ----------

def encode_name(domain):
    return b"".join(struct.pack("B", len(p)) + p.encode() for p in domain.split(".") if p) + b"\x00"


def build_query(domain, qtype=QTYPE_A, do=False, qid=None):
    """-> (qid, packet)。do=True でEDNS0 OPTレコードを追加しDNSSEC OKビットを立てる。"""
    qid = random.randint(0, 65535) if qid is None else qid
    arcount = 1 if do else 0
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, arcount)  # 0x0100 = RD
    packet = header + encode_name(domain) + struct.pack(">HH", qtype, 1)
    if do:
        # OPT: name=root(0x00), type=41, class=UDPペイロードサイズ, ttl=拡張RCODE|version|フラグ, rdlen=0
        packet += b"\x00" + struct.pack(">HHIH", OPT_TYPE, EDNS_UDP_SIZE, EDNS_DO, 0)
    return qid, packet


def read_name(data, pos):
    """圧縮ポインタを辿って名前を読む。-> (名前, ポインタを辿る前の次の位置)"""
    labels = []
    end = None
    for _ in range(128):  # ポインタのループを踏んでも無限に回らないようにする
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                break
            if end is None:
                end = pos + 2
            pos = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return ".".join(labels), (end if end is not None else pos)


def parse_response(data):
    """DNS応答 -> {"rcode","ad","ra","tc","ancount","a","ptr","cname"}"""
    if len(data) < 12:
        raise ValueError(f"応答が短すぎます ({len(data)}バイト)")
    qid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
    result = {
        "id": qid,
        "rcode": flags & 0xF,
        "ad": bool(flags >> 5 & 1),     # Authenticated Data (リゾルバがDNSSEC検証済み)
        "ra": bool(flags >> 7 & 1),
        "tc": bool(flags >> 9 & 1),
        "ancount": ancount,
        "a": [], "ptr": [], "cname": [],
    }
    pos = 12
    try:
        for _ in range(qdcount):
            _, pos = read_name(data, pos)
            pos += 4
        for _ in range(ancount):
            _, pos = read_name(data, pos)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == QTYPE_A and rdlen == 4:
                result["a"].append(socket.inet_ntoa(data[pos:pos + 4]))
            elif rtype == QTYPE_PTR:
                result["ptr"].append(read_name(data, pos)[0])
            elif rtype == 5:  # CNAME
                result["cname"].append(read_name(data, pos)[0])
            pos += rdlen
    except (struct.error, IndexError):
        result["truncated_parse"] = True  # RRSIG等で切れていてもヘッダの判定は使える
    return result


def query_udp(server, domain, qtype=QTYPE_A, do=False, timeout=3.0, attempts=2):
    """UDP/53で問い合わせる。-> parse_response の結果 (+ "ms") / 失敗時は {"error": ...}"""
    last_error = "timeout"
    for _ in range(attempts):
        qid, packet = build_query(domain, qtype, do)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            start = time.perf_counter()
            sock.sendto(packet, (server, 53))
            while True:  # 別のクエリの遅延応答が混ざることがあるのでIDで選別する
                data, _ = sock.recvfrom(4096)
                if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                    break
            parsed = parse_response(data)
            parsed["ms"] = round((time.perf_counter() - start) * 1000, 1)
            return parsed
        except socket.timeout:
            last_error = "応答なし (タイムアウト)"
        except OSError as e:
            last_error = f"{type(e).__name__}: {e}"
            break
        except ValueError as e:
            last_error = str(e)
            break
        finally:
            sock.close()
    return {"error": last_error}


# ---------- 暗号化DNS (DoT / DoH) ----------

def _tls_connect(ip, port, sni, timeout):
    """-> (TLSソケット, 証明書検証できたか, 備考)。検証に失敗しても到達性は見たいので検証なしで再試行する。"""
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, port), timeout=timeout)
        return ctx.wrap_socket(raw, server_hostname=sni), True, ""
    except ssl.SSLCertVerificationError as e:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=timeout)
        note = f"証明書検証は失敗 ({e.verify_message or e.reason})。到達性は検証なしで確認"
        return ctx.wrap_socket(raw), False, note


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("接続が途中で切れました")
        buf += chunk
    return buf


def dot_query(ip, sni, domain="example.com", timeout=6.0):
    """DNS over TLS (853/tcp)。TLSハンドシェイクだけでなく実際に1問い合わせて確認する。"""
    try:
        tls, verified, note = _tls_connect(ip, 853, sni, timeout)
    except OSError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    try:
        _qid, packet = build_query(domain)
        tls.sendall(struct.pack(">H", len(packet)) + packet)  # DoTは2バイトの長さ前置き
        length = struct.unpack(">H", _recv_exact(tls, 2))[0]
        parsed = parse_response(_recv_exact(tls, length))
        return {"ok": True, "tls": tls.version(), "cert_verified": verified, "note": note,
                "rcode": parsed["rcode"], "ips": parsed["a"]}
    except (OSError, ValueError, struct.error) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            tls.close()
        except OSError:
            pass


def doh_query(ip, sni, domain="example.com", timeout=6.0):
    """DNS over HTTPS (443/tcp、RFC 8484 wireformat の GET)。"""
    try:
        tls, verified, note = _tls_connect(ip, 443, sni, timeout)
    except OSError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    try:
        _qid, packet = build_query(domain)
        dns_param = base64.urlsafe_b64encode(packet).rstrip(b"=").decode()
        tls.sendall((f"GET /dns-query?dns={dns_param} HTTP/1.1\r\nHost: {sni}\r\n"
                     "Accept: application/dns-message\r\nUser-Agent: network-diag/1.0\r\n"
                     "Connection: close\r\n\r\n").encode())
        # chunked/Content-Length の処理をstdlibに任せる
        resp = http.client.HTTPResponse(tls, method="GET")
        resp.begin()
        body = resp.read()
        out = {"ok": True, "status": resp.status, "tls": tls.version(),
               "cert_verified": verified, "note": note, "ips": []}
        if resp.status == 200:
            parsed = parse_response(body)
            out.update(rcode=parsed["rcode"], ips=parsed["a"])
        elif resp.status == 505:
            # Quad9等はHTTP/2必須。http.clientはHTTP/1.1のみなので問い合わせは通らないが、
            # 505が返っている時点で443には到達できている(=塞がれていない)。
            out["note"] = (note + " / " if note else "") + "HTTP/2必須のため問い合わせ自体は本ツールでは不可"
        else:
            out["note"] = (note + " / " if note else "") + f"HTTP {resp.status}"
        return out
    except (OSError, ValueError, struct.error, http.client.HTTPException) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            tls.close()
        except OSError:
            pass


# ---------- 判定 (実測と分けて、断定しすぎない文言にする) ----------

def nxdomain_verdict(resp):
    """存在しない名前への応答 -> (実測文, 判定文, タグ)"""
    if "error" in resp:
        return resp["error"], "判定不可", "muted"
    measured = f"{rcode_name(resp['rcode'])} / Aレコード{len(resp['a'])}件"
    if resp["a"]:
        return (measured + ": " + ", ".join(resp["a"]),
                "NXDOMAINハイジャックの疑い (存在しない名前にIPが返っている)", "bad")
    if resp["rcode"] == 3:
        return measured, "正常 (NXDOMAINが返っている)", "good"
    if resp["rcode"] == 0:
        return measured, "NOERROR/回答0件。ハイジャックではないが本来はNXDOMAIN", "warn"
    return measured, "NXDOMAIN以外の応答。要確認", "warn"


def org_of(ip):
    info = nd.lookup_ip_info(ip)
    return (info or {}).get("org") or ""


def consistency_verdict(per_server):
    """[{"server","ips","orgs"}] -> (判定文, タグ)。CDNのIP差異を改ざんと断定しないこと。"""
    responded = [p for p in per_server if p["ips"]]
    if len(responded) < 2:
        return "比較対象が足りず判定不可", "muted"
    ipsets = {frozenset(p["ips"]) for p in responded}
    orgsets = [frozenset(o for o in p["orgs"] if o) for p in responded]
    if len(ipsets) == 1:
        return "全リゾルバでIPが完全一致", "good"
    if all(orgsets) and len(set(orgsets)) == 1:
        return "IPは異なるが全リゾルバ同一組織 (CDNの正常な挙動)", "good"
    if not all(orgsets):
        return "IPが異なり組織を特定できないものがある。目視で確認を", "warn"
    common = set.intersection(*(set(o) for o in orgsets))
    if common:
        return "IPも組織構成も異なるが共通の組織あり (CDN/GeoDNSでも起きる)。目視で確認を", "warn"
    return "リゾルバ間で組織がまったく異なる。CDNでも起こりうるが要確認", "warn"


def dnssec_verdict(ad_results, broken):
    """(署名済みドメインのAD結果, 壊れた署名への応答) -> (実測文, 判定文, タグ)"""
    ok = [d for d, r in ad_results.items() if r.get("ad")]
    measured = "  ".join(f"{d}: AD={'1' if r.get('ad') else '0'}" if "error" not in r
                         else f"{d}: {r['error']}" for d, r in ad_results.items())
    if "error" in broken:
        broken_txt, validates_broken = broken["error"], None
    else:
        broken_txt = f"{DNSSEC_BROKEN}: {rcode_name(broken['rcode'])}/{len(broken['a'])}件"
        validates_broken = broken["rcode"] == 2 or (broken["rcode"] != 0 and not broken["a"])
    measured += "   " + broken_txt

    if ok and validates_broken:
        return measured, "DNSSEC検証あり (ADが立ち、壊れた署名は解決されない)", "good"
    if ok:
        return measured, "ADは立つが壊れた署名も解決できてしまう。要確認", "warn"
    if validates_broken:
        return measured, "ADは立たないが壊れた署名は拒否。上流で検証されている可能性", "warn"
    if any("error" in r for r in ad_results.values()):
        return measured, "判定不可 (応答が得られず)", "muted"
    return measured, "DNSSEC検証なし (ADが立たず、壊れた署名も解決される)", "warn"


def encrypted_verdict(res, label):
    if not res.get("ok"):
        return res.get("error", "失敗"), f"{label}に到達できない (ポートが塞がれている可能性)", "warn"
    parts = [res.get("tls") or "TLS"]
    if res.get("ips"):
        parts.append(", ".join(res["ips"][:3]))
    if res.get("status"):
        parts.append(f"HTTP {res['status']}")
    if not res.get("cert_verified", True):
        parts.append("証明書検証NG")
    measured = " / ".join(str(p) for p in parts)
    if res.get("note"):
        measured += f"  ({res['note']})"
    if res.get("ips"):
        return measured, f"{label}到達OK (問い合わせも成功)", "good"
    return measured, f"{label}のポートには到達できている", "good"


def ptr_verdict(ip, resp):
    if "error" in resp:
        return resp["error"], "判定不可", "muted"
    if resp["ptr"]:
        return ", ".join(resp["ptr"]), "逆引きあり", "good"
    private = ip.startswith(("192.168.", "10.", "127.", "169.254.")) or ip.startswith("172.")
    note = "逆引きなし (プライベートIPでは正常)" if private else "逆引きなし"
    return rcode_name(resp["rcode"]), note, "good" if private else "warn"


# ---------- 監査本体 (ワーカースレッドから呼ばれる) ----------

def random_nonexistent(suffix):
    return f"{random.getrandbits(48):012x}.{suffix}"


def audit_nxdomain(servers):
    rows, raw = [], {}
    for domain in (random_nonexistent("example.invalid"), random_nonexistent("com")):
        children = []
        for label, ip in servers:
            resp = query_udp(ip, domain)
            raw.setdefault(domain, {})[ip] = resp
            measured, verdict, tag = nxdomain_verdict(resp)
            children.append({"label": f"{label} ({ip})", "measured": measured, "verdict": verdict, "tag": tag})
        worst = "bad" if any(c["tag"] == "bad" for c in children) else \
                "warn" if any(c["tag"] == "warn" for c in children) else "good"
        rows.append({"label": domain, "measured": "存在しないはずのドメイン",
                     "verdict": "ハイジャックあり" if worst == "bad" else "全リゾルバ正常" if worst == "good" else "要確認",
                     "tag": worst, "children": children})
    return {"rows": rows, "raw": raw}


def audit_consistency(servers, domains):
    rows, raw = [], {}
    for domain in domains:
        per_server, children = [], []
        for label, ip in servers:
            resp = query_udp(ip, domain)
            raw.setdefault(domain, {})[ip] = resp
            if "error" in resp:
                children.append({"label": f"{label} ({ip})", "measured": resp["error"],
                                 "verdict": "-", "tag": "muted"})
                per_server.append({"server": ip, "ips": [], "orgs": []})
                continue
            orgs = sorted({org_of(a) for a in resp["a"] if org_of(a)})
            per_server.append({"server": ip, "ips": resp["a"], "orgs": orgs})
            children.append({"label": f"{label} ({ip})",
                             "measured": ", ".join(resp["a"]) or f"{rcode_name(resp['rcode'])} / 回答0件",
                             "verdict": " / ".join(orgs) or "組織不明", "tag": "muted"})
        verdict, tag = consistency_verdict(per_server)
        rows.append({"label": domain, "measured": f"{len(per_server)}リゾルバに問い合わせ",
                     "verdict": verdict, "tag": tag, "children": children})
    return {"rows": rows, "raw": raw}


def audit_dnssec(servers):
    rows, raw = [], {}
    for label, ip in servers:
        ad_results = {d: query_udp(ip, d, do=True) for d in DNSSEC_SIGNED}
        broken = query_udp(ip, DNSSEC_BROKEN, do=True)
        raw[ip] = {"signed": ad_results, "broken": broken}
        measured, verdict, tag = dnssec_verdict(ad_results, broken)
        rows.append({"label": f"{label} ({ip})", "measured": measured, "verdict": verdict, "tag": tag})
    return {"rows": rows, "raw": raw}


def audit_encrypted(hosts):
    rows, raw = [], {}
    for ip, sni in hosts:
        children = []
        for proto, fn, port in (("DoH", doh_query, 443), ("DoT", dot_query, 853)):
            res = fn(ip, sni)
            raw.setdefault(ip, {})[proto] = res
            measured, verdict, tag = encrypted_verdict(res, f"{proto} ({port}/tcp)")
            children.append({"label": proto, "measured": measured, "verdict": verdict, "tag": tag})
        tag = "good" if all(c["tag"] == "good" for c in children) else "warn"
        rows.append({"label": f"{ip} ({sni})", "measured": "DoH 443 / DoT 853",
                     "verdict": "両方通る (ルーターは塞いでいない)" if tag == "good" else "一部到達できず",
                     "tag": tag, "children": children})
    return {"rows": rows, "raw": raw}


def audit_ptr(targets, resolver):
    rows, raw = [], {}
    for label, ip in targets:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        resp = query_udp(resolver, rev, qtype=QTYPE_PTR)
        raw[ip] = resp
        measured, verdict, tag = ptr_verdict(ip, resp)
        rows.append({"label": f"{label} ({ip})", "measured": measured, "verdict": verdict, "tag": tag})
    return {"rows": rows, "raw": raw}


SECTION_TITLES = {
    "nxdomain": "1. NXDOMAINハイジャック検出",
    "consistency": "2. 応答の一致検証 (リゾルバ間のAレコード比較)",
    "dnssec": "3. DNSSEC検証の有無 (DOビット付き問い合わせのADフラグ)",
    "encrypted": "4. DoH / DoT 対応状況",
    "ptr": "5. 逆引き (PTR)",
}


# ---------- タブ本体 ----------

COLUMNS = [("measured", "実測できたこと", 430), ("verdict", "判定", 430)]


class DnsAuditTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self._stop = threading.Event()
        self._thread = None
        self.result = {}
        self.gateway = None

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        self.run_btn = ttk.Button(top, text="▶  監査開始", style="Accent.TButton", command=self.start)
        self.run_btn.pack(side="left", padx=4)
        ttk.Button(top, text="⬇  JSON保存", command=self.export).pack(side="left", padx=4)
        ttk.Label(top, text="DNSの応答時間ではなく、応答の正しさ・安全性を確認します").pack(side="left", padx=16)

        self.status = ttk.Label(parent, text="未実行", padding=(6, 4))
        self.status.pack(fill="x")

        # 実測値の行が長くなるので横スクロールも出す (Treeviewは溢れた文字を黙って切る)
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True, padx=4, pady=(4, 8))
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(box, columns=[c[0] for c in COLUMNS], show="tree headings", height=22)
        self.tree.heading("#0", text="項目")
        self.tree.column("#0", width=300, minwidth=200, stretch=False)
        for key, head, width in COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width, minwidth=200, anchor="w", stretch=False)
        vsb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(box, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.on_theme_changed()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        for tag in ("good", "warn", "bad", "muted"):
            self.tree.tag_configure(tag, foreground=t[tag] if tag != "muted" else t["muted"])
        # sv_ttk が style map に -foreground を設定しており、そのままだとタグ色が無視される。
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
        self.tree.delete(*self.tree.get_children())
        self.result = {}
        self.run_btn.config(state="disabled")
        self._set_status("監査を開始します...", "muted")
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    # ---- ワーカー ----

    def _worker(self):
        try:
            self._post(self._set_status, "デフォルトゲートウェイを検出中...", "muted")
            self.gateway = nd.get_default_gateway()
            servers = ([("ルーター", self.gateway)] if self.gateway else []) + \
                      [(name, ip) for ip, name in PUBLIC_RESOLVERS]
            self.result = {"timestamp": datetime.now().isoformat(timespec="seconds"),
                           "gateway": self.gateway,
                           "servers": [{"label": l, "ip": i} for l, i in servers]}

            steps = [
                ("nxdomain", lambda: audit_nxdomain(servers)),
                ("consistency", lambda: audit_consistency(servers, CONSISTENCY_DOMAINS)),
                ("dnssec", lambda: audit_dnssec(servers)),
                ("encrypted", lambda: audit_encrypted(ENCRYPTED_HOSTS)),
                ("ptr", lambda: audit_ptr(self._ptr_targets(), self.gateway or "1.1.1.1")),
            ]
            for i, (key, fn) in enumerate(steps, 1):
                if self._stop.is_set():
                    return
                self._post(self._set_status, f"[{i}/{len(steps)}] {SECTION_TITLES[key]} ...", "muted")
                try:
                    data = fn()
                except Exception as e:  # 1項目が転んでも残りは出す
                    data = {"rows": [{"label": "エラー", "measured": f"{type(e).__name__}: {e}",
                                      "verdict": "判定不可", "tag": "bad"}], "raw": {}}
                self.result[key] = data
                self._post(self._render_section, key, data)

            if self._stop.is_set():
                return
            path = self._save()
            self._post(self._set_status, f"✓ 監査完了  保存: {path.name}", "good")
        except Exception as e:
            self._post(self._set_status, f"監査に失敗しました: {type(e).__name__}: {e}", "bad")
        finally:
            self._post(lambda: self.run_btn.config(state="normal"))

    def _ptr_targets(self):
        targets = []
        if self.gateway:
            targets.append(("ゲートウェイ", self.gateway))
        public = nd.lookup_ip_info()
        if public and public.get("ip"):
            targets.append(("自分の公開IP", public["ip"]))
            self.result["public_ip_info"] = public
        targets += [(name, ip) for ip, name in PUBLIC_RESOLVERS]
        return targets

    def _post(self, fn, *args):
        self.ctx.root.after(0, lambda: fn(*args))

    # ---- 表示 ----

    def _set_status(self, text, tag="muted"):
        t = self.ctx.theme
        self.status.config(text=text, foreground=t.get(tag, t["muted"]))

    def _render_section(self, key, data):
        parent = self.tree.insert("", "end", text=SECTION_TITLES[key], open=True, tags=("muted",))
        for row in data.get("rows", []):
            self._insert_row(parent, row)

    def _insert_row(self, parent, row):
        node = self.tree.insert(parent, "end", text=row["label"], open=True,
                                values=(row.get("measured", ""), row.get("verdict", "")),
                                tags=(row.get("tag", "muted"),))
        for child in row.get("children", []):
            self._insert_row(node, child)

    # ---- 保存 ----

    def _save(self):
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"dnsaudit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.write_text(json.dumps(self.result, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def export(self):
        if not self.result:
            self._set_status("保存する結果がありません。先に監査を実行してください", "warn")
            return
        self._set_status(f"✓ 出力: {self._save().name}", "good")


# ---------- 自己テスト (ネットワーク不要) ----------

def _selftest():
    # --- クエリ組み立て ---
    assert encode_name("google.com") == b"\x06google\x03com\x00"
    assert encode_name("a.bc") == b"\x01a\x02bc\x00"

    qid, pkt = build_query("google.com", qid=0x1234)
    assert struct.unpack(">HHHHHH", pkt[:12]) == (0x1234, 0x0100, 1, 0, 0, 0), pkt[:12]
    assert pkt[12:] == b"\x06google\x03com\x00" + struct.pack(">HH", 1, 1)
    assert qid == 0x1234

    # DOビット付き: ARCOUNT=1 になり、末尾にOPTレコード(11バイト)が付く
    _, do_pkt = build_query("example.com", do=True, qid=1)
    assert struct.unpack(">H", do_pkt[10:12])[0] == 1, "ARCOUNTが1でない"
    opt = do_pkt[-11:]
    assert opt == b"\x00" + struct.pack(">HHIH", 41, 4096, 0x8000, 0), opt.hex()
    assert len(do_pkt) == len(build_query("example.com", qid=1)[1]) + 11

    _, ptr_pkt = build_query("1.0.0.127.in-addr.arpa", qtype=QTYPE_PTR, qid=2)
    assert ptr_pkt[-4:] == struct.pack(">HH", 12, 1)

    # --- 応答パース: NXDOMAIN (実測した 1.1.1.1 の応答と同じフラグ 0x8183) ---
    question = b"\x01x\x07invalid\x00" + struct.pack(">HH", 1, 1)
    nx = struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0) + question
    r = parse_response(nx)
    assert r["rcode"] == 3 and r["a"] == [] and r["ad"] is False and r["ra"] is True, r
    assert rcode_name(r["rcode"]) == "NXDOMAIN"

    # --- 応答パース: ADフラグ + Aレコード (フラグ 0x81a0 = QR|RD|RA|AD) ---
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("1.2.3.4")
    ok = struct.pack(">HHHHHH", 0x1234, 0x81a0, 1, 1, 0, 0) + question + answer
    r = parse_response(ok)
    assert r["ad"] is True and r["rcode"] == 0 and r["a"] == ["1.2.3.4"], r
    # ADビットだけ落とすと False になること (ビット位置5の取り違え回帰テスト)
    assert parse_response(struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + question + answer)["ad"] is False
    # SERVFAIL (壊れた署名を弾いたときに実測された応答)
    assert parse_response(struct.pack(">HHHHHH", 1, 0x8182, 1, 0, 0, 0) + question)["rcode"] == 2

    # --- PTR + 圧縮ポインタ ---
    q2 = b"\x011\x07example\x03com\x00" + struct.pack(">HH", 12, 1)
    rdata = b"\x04host\xc0\x0e"  # オフセット14 = "example" ラベルの先頭
    ptr_resp = (struct.pack(">HHHHHH", 9, 0x8180, 1, 1, 0, 0) + q2 +
                b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 60, len(rdata)) + rdata)
    assert parse_response(ptr_resp)["ptr"] == ["host.example.com"], parse_response(ptr_resp)
    assert read_name(b"\x03abc\x00", 0) == ("abc", 5)

    # 壊れたパケットで例外を投げないこと
    assert parse_response(struct.pack(">HHHHHH", 1, 0x8180, 1, 3, 0, 0) + question).get("truncated_parse")
    try:
        parse_response(b"\x00\x01")
        raise AssertionError("短すぎる応答でValueErrorが出ていない")
    except ValueError:
        pass

    # --- NXDOMAIN判定 ---
    assert nxdomain_verdict({"rcode": 3, "a": []})[2] == "good"
    hijack = nxdomain_verdict({"rcode": 0, "a": ["1.2.3.4"]})
    assert hijack[2] == "bad" and "1.2.3.4" in hijack[0], hijack
    assert nxdomain_verdict({"rcode": 0, "a": []})[2] == "warn"
    assert nxdomain_verdict({"error": "応答なし"})[2] == "muted"

    # --- 一致検証: CDNのIP差異を「改ざん」と断定しないこと ---
    akamai = "AS16625 Akamai Technologies, Inc."
    cdn = [{"server": "a", "ips": ["104.71.152.189"], "orgs": [akamai]},
           {"server": "b", "ips": ["23.36.100.2"], "orgs": [akamai]},
           {"server": "c", "ips": ["184.25.63.82"], "orgs": [akamai]}]
    v, tag = consistency_verdict(cdn)
    assert tag == "good" and "CDN" in v, (v, tag)  # www.softbank.jp の実測パターン
    same = [{"server": "a", "ips": ["104.16.132.229"], "orgs": ["AS13335 Cloudflare"]},
            {"server": "b", "ips": ["104.16.132.229"], "orgs": ["AS13335 Cloudflare"]}]
    assert consistency_verdict(same)[1] == "good"
    odd = [{"server": "a", "ips": ["104.16.132.229"], "orgs": ["AS13335 Cloudflare"]},
           {"server": "b", "ips": ["203.0.113.9"], "orgs": ["AS64496 Somebody Else"]}]
    v, tag = consistency_verdict(odd)
    assert tag == "warn" and "断" not in v, (v, tag)  # 危険とは断定しない
    assert consistency_verdict([{"server": "a", "ips": [], "orgs": []}])[1] == "muted"

    # --- DNSSEC判定 (実測パターンをそのまま食わせる) ---
    # 1.1.1.1/8.8.8.8/9.9.9.9: AD=1、壊れた署名はSERVFAIL
    v = dnssec_verdict({"cloudflare.com": {"ad": True, "rcode": 0, "a": ["1.2.3.4"]}},
                       {"rcode": 2, "a": []})
    assert v[2] == "good" and "検証あり" in v[1], v
    # 光BBユニット: AD=0、壊れた署名も解決できてしまう
    v = dnssec_verdict({"cloudflare.com": {"ad": False, "rcode": 0, "a": ["1.2.3.4"]}},
                       {"rcode": 0, "a": ["96.99.227.255"]})
    assert v[2] == "warn" and "検証なし" in v[1], v
    assert "AD=0" in v[0], v
    assert dnssec_verdict({"x": {"error": "応答なし"}}, {"error": "応答なし"})[2] == "muted"

    # --- DoH/DoT判定 ---
    assert encrypted_verdict({"ok": True, "tls": "TLSv1.3", "ips": ["1.2.3.4"]}, "DoT")[2] == "good"
    v = encrypted_verdict({"ok": True, "tls": "TLSv1.3", "status": 505, "ips": [],
                           "note": "HTTP/2必須"}, "DoH")
    assert v[2] == "good" and "到達" in v[1], v  # 505でも443には届いている
    assert encrypted_verdict({"ok": False, "error": "ConnectionRefusedError"}, "DoT")[2] == "warn"

    # --- PTR判定 ---
    assert ptr_verdict("1.1.1.1", {"rcode": 0, "ptr": ["one.one.one.one"]})[2] == "good"
    v = ptr_verdict("192.168.3.1", {"rcode": 3, "ptr": []})
    assert v[2] == "good" and "プライベート" in v[1], v
    assert ptr_verdict("126.1.32.112", {"rcode": 3, "ptr": []})[2] == "warn"

    dom = random_nonexistent("example.invalid")
    assert dom.endswith(".example.invalid") and len(dom.split(".")[0]) == 12

    print("dnsaudit selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1100x650")
    root.title("DNS詳細監査")
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
    tab = DnsAuditTab(frame, ctx)
    if "--auto" in sys.argv:
        root.after(300, tab.start)
        root.after(90000, lambda: (tab.on_close(), root.destroy()))
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
