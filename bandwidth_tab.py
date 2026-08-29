#!/usr/bin/env python3
"""帯域使用の時系列記録 + VPN/プロキシ検出タブ。

■ この方式を選んだ理由 (実機で確認済み / 2026-08-24, 管理者権限なしのユーザーで検証)
既存の「通信量」タブは生ソケット(SIO_RCVALL)で管理者権限が要り、しかも現在値しか出ない。
このタブは管理者権限なしで動く手段だけを使い、代わりに「何が取れないか」を明示する。

  psutil.net_io_counters(pernic=True)  -> ○ 動く。NIC単位の累積バイト。差分でスループットが正確に出る。
  psutil.net_connections(kind='inet')  -> ○ 動く (実測 224接続中 199件にPIDが付いた)。ただしバイト数は無い。
  C:\\Windows\\System32\\sru\\SRUDB.dat -> × PermissionDenied。Windowsが持つ唯一のプロセス別
                                            ネットワーク使用量DB(設定アプリの「データ使用状況」の実体)だが
                                            管理者権限が要る。
  Get-Counter '\\Process(*)\\IO Read Bytes/sec' -> △ 権限なしでも動くが、これはディスク+パイプ+ネットの
                                            合算I/O。実測でNICが暇なときに 'code' が 2.5MB/s を示した
                                            (＝ほぼディスク)。ネットワーク量として出すと嘘になるので使わない。
  ETW (netsh trace)                     -> 重いので不採用(指示どおり)。

結論: **プロセス別のバイト数は管理者権限なしでは取れない。** よってこのタブは
「NIC全体のバイト数は正確に。プロセス別は接続数だけ」という切り分けで作ってある。
"""
import collections
import csv
import json
import os
import re
import socket
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import network_diag as nd
import traffic_monitor as tm

try:
    import psutil
except ImportError:  # 単体起動時に分かるようにここでは落とさない
    psutil = None

JSONL_NAME = "bandwidth.jsonl"
DEFAULT_INTERVAL_S = 2.0
MAX_MEM_SAMPLES = 20000   # 画面用に保持する上限。ファイルには全件残る(2秒間隔で約11時間分)
CONN_REFRESH_EVERY = 3    # 何サンプルごとに接続一覧を取り直すか
DOWN_COLOR = "#58a6ff"
UP_COLOR = "#f0883e"

RANGES = [("直近5分", 300), ("直近15分", 900), ("直近1時間", 3600),
          ("直近6時間", 21600), ("保持分すべて", 0)]

# 仮想NIC判定表。上から順に最初に当たったものを採用するので、具体的なものを先に置くこと。
# (pattern, ラベル, VPNらしさ) — 名前と InterfaceDescription を小文字化して照合する。
# **名前で当たっただけではVPNを使っている証拠にはならない**。増やすのはこのリストだけでよい。
VIRTUAL_NIC_RULES = [
    (r"openvpn", "VPN (OpenVPN)", True),
    (r"wireguard|\bwg\d", "VPN (WireGuard)", True),
    (r"tailscale", "VPN (Tailscale)", True),
    (r"zerotier", "VPN (ZeroTier)", True),
    (r"nordlynx|nordvpn", "VPN (NordVPN)", True),
    (r"expressvpn|proton ?vpn|mullvad|surfshark|cyberghost|windscribe|private internet access",
     "VPN (商用VPNクライアント)", True),
    (r"cisco ?anyconnect|globalprotect|pulse ?secure|forti(client|net)|sonicwall|check ?point|"
     r"zscaler|netskope|ivanti", "VPN/SASE (企業クライアント)", True),
    (r"tap-?windows|tap-?adapter|\btap\b", "VPN仮想NIC (TAP)", True),
    (r"softether|\bvpn\b|\btun\b|\btunnel\b", "VPN (汎用トンネル)", True),
    (r"hyper-?v|vethernet", "仮想化 (Hyper-V)", False),
    (r"\bwsl\b|windows subsystem for linux", "仮想化 (WSL)", False),
    (r"docker", "仮想化 (Docker)", False),
    (r"virtualbox|vmware|parallels|\bvbox", "仮想化 (VM)", False),
    (r"teredo|6to4|isatap|ip-https", "IPv6トンネル (Windows標準)", False),
    (r"npcap loopback|loopback", "ループバック", False),
    (r"bluetooth", "Bluetooth PAN", False),
    (r"wan miniport", "WANミニポート (Windows標準)", False),
    (r"virtual|仮想", "その他の仮想アダプタ", False),
]


# ---------- 純粋関数 (自己テスト対象) ----------

def classify_adapter(name, description):
    """アダプタ名/説明から (ラベル, VPNらしさ) を返す。仮想と判断できなければ None。"""
    hay = f"{name or ''} {description or ''}".lower()
    for pattern, label, vpn_like in VIRTUAL_NIC_RULES:
        if re.search(pattern, hay):
            return label, vpn_like
    return None


def counter_snapshot():
    """{NIC名: (累積送信バイト, 累積受信バイト)}。ループバックは除く。"""
    if psutil is None:
        return {}
    out = {}
    for nic, c in psutil.net_io_counters(pernic=True).items():
        if "loopback" in nic.lower() or nic.lower().startswith("lo"):
            continue
        out[nic] = (c.bytes_sent, c.bytes_recv)
    return out


def diff_counters(prev, cur, dt):
    """累積カウンタの差分から (合計上りB/s, 合計下りB/s, {NIC: (上り, 下り)}) を出す。

    ・prev に無いNIC(この区間で現れた)は基準が無いので捨てる
    ・cur に無いNIC(消えた)は自然に無視される
    ・カウンタが減っていたらその区間は捨てる。32bitラップとドライバのリセット/再有効化は
      区別できず、差を推定すると巨大な偽ピークになるため。
      # ponytail: ラップは復元せず捨てる。1サンプル欠けるだけ。復元したいなら
      #           psutil の値が64bitか32bitかをNICごとに判定する仕組みが要る。
    """
    if dt <= 0:
        return 0.0, 0.0, {}
    per_nic, total_up, total_down = {}, 0.0, 0.0
    for nic, (sent, recv) in cur.items():
        before = prev.get(nic)
        if before is None:
            continue
        d_sent, d_recv = sent - before[0], recv - before[1]
        if d_sent < 0 or d_recv < 0:
            continue
        up, down = d_sent / dt, d_recv / dt
        per_nic[nic] = (up, down)
        total_up += up
        total_down += down
    return total_up, total_down, per_nic


def scale(v, v0, v1, p0, p1):
    """値域 [v0,v1] を画面座標 [p0,p1] へ線形写像。v1==v0 なら中央に置く。"""
    if v1 == v0:
        return (p0 + p1) / 2.0
    return p0 + (v - v0) * (p1 - p0) / (v1 - v0)


def nice_ceil(v):
    """軸の上限を 1/2/5×10^n に切り上げる。"""
    if not v or v <= 0:
        return 1.0
    e = 10 ** (len(f"{int(v):d}") - 1) if v >= 1 else 10 ** -3
    while e * 10 <= v:
        e *= 10
    for m in (1, 2, 5):
        if m * e >= v:
            return float(m * e)
    return float(10 * e)


def fmt_bps(n):
    """バイト毎秒を人間可読に。network_diag_gui.format_bytes と同じ考え方だが、
    あちらはGUI本体側にありタブから import すると循環するのでここに持つ。"""
    n = float(n or 0)
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= div:
            return f"{n / div:.1f}{unit}/s"
    return f"{n:.0f}B/s"


def fmt_mbps(n):
    return f"{float(n or 0) * 8 / 1e6:.2f}Mbps"


def jsonl_path():
    return nd.RESULTS_DIR / JSONL_NAME


def read_jsonl_tail(path, maxlen=MAX_MEM_SAMPLES):
    """末尾 maxlen 行を読み、壊れた行・型の違う行は黙って捨てる。ファイルが無ければ空。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = collections.deque(f, maxlen=maxlen)
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        t, up, down = rec.get("t"), rec.get("up"), rec.get("down")
        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (t, up, down)):
            out.append(rec)
    return out


def append_jsonl(path, rec):
    path.parent.mkdir(exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def parse_proxy(reg, env):
    """レジストリの Internet Settings と環境変数からプロキシ設定をまとめる。
    reg は値が欠けていることも None であることもある。"""
    reg = reg if isinstance(reg, dict) else {}
    raw_enable = reg.get("ProxyEnable")
    try:
        enabled = bool(int(raw_enable))
    except (TypeError, ValueError):
        enabled = bool(raw_enable) and raw_enable not in ("", "0")
    server = (reg.get("ProxyServer") or "").strip() or None
    pac = (reg.get("AutoConfigURL") or "").strip() or None
    bypass = (reg.get("ProxyOverride") or "").strip() or None
    env_proxies = {k.upper(): v for k, v in (env or {}).items()
                   if k.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY") and v}
    return {
        "enabled": enabled and bool(server),
        "server": server,
        "pac": pac,
        "bypass": bypass,
        "env": env_proxies,
        "active": bool((enabled and server) or pac
                       or any(k != "NO_PROXY" for k in env_proxies)),
    }


def summarize(points):
    """(t, up, down) の列から件数・平均・ピークを出す。0件/1件でも落ちないこと。"""
    if not points:
        return {"count": 0, "avg_up": 0.0, "avg_down": 0.0,
                "peak_up": None, "peak_down": None, "start": None, "end": None}
    peak_up = max(points, key=lambda p: p[1])
    peak_down = max(points, key=lambda p: p[2])
    n = len(points)
    return {
        "count": n,
        "avg_up": sum(p[1] for p in points) / n,
        "avg_down": sum(p[2] for p in points) / n,
        "peak_up": (peak_up[0], peak_up[1]),
        "peak_down": (peak_down[0], peak_down[2]),
        "start": points[0][0],
        "end": points[-1][0],
    }


def bucket_by_pixel(points, t0, t1, x0, x1):
    """点が横幅より多いとき、1px に1点へ潰す(最大値を残すのでピークは消えない)。
    -> [(x, up, down), ...] を x 昇順で返す。"""
    buckets = {}
    for t, up, down in points:
        x = int(round(scale(t, t0, t1, x0, x1)))
        prev = buckets.get(x)
        buckets[x] = (max(up, prev[0]), max(down, prev[1])) if prev else (up, down)
    return [(x, v[0], v[1]) for x, v in sorted(buckets.items())]


def _json_list(text):
    """PowerShell 5.1 の ConvertTo-Json は要素1個の配列をオブジェクトに潰すのでリストへ戻す。"""
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


# ---------- 実機からの収集 (ネットワーク/PowerShell が要る) ----------

def collect_adapters():
    out = nd.ps("Get-NetAdapter -ErrorAction SilentlyContinue | "
                "Select-Object Name,InterfaceDescription,Status,InterfaceIndex | "
                "ConvertTo-Json -Compress", timeout=30)
    rows = []
    for a in _json_list(out):
        name, desc = a.get("Name") or "", a.get("InterfaceDescription") or ""
        hit = classify_adapter(name, desc)
        rows.append({"name": name, "desc": desc, "status": a.get("Status"),
                     "index": a.get("InterfaceIndex"),
                     "category": hit[0] if hit else None,
                     "vpn_like": bool(hit and hit[1])})
    return rows


def collect_routes():
    out = nd.ps("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
                "Sort-Object RouteMetric | "
                "Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | "
                "ConvertTo-Json -Compress", timeout=30)
    return _json_list(out)


def collect_proxy():
    out = nd.ps(
        "$p = Get-ItemProperty -Path "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
        "-ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ProxyEnable=$p.ProxyEnable; ProxyServer=$p.ProxyServer; "
        "AutoConfigURL=$p.AutoConfigURL; ProxyOverride=$p.ProxyOverride} | ConvertTo-Json -Compress",
        timeout=30)
    reg = _json_list(out)
    return parse_proxy(reg[0] if reg else {}, os.environ)


def nic_of_ip(ip):
    """そのIPを持つNIC名。psutil.net_if_addrs から逆引きする。"""
    if psutil is None or not ip:
        return None
    for nic, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and a.address == ip:
                return nic
    return None


def collect_connections(limit=30):
    """プロセス別の接続数。**バイト数はここでは取れない**(Windowsが権限なしでは出さない)。"""
    if psutil is None:
        return [], "psutil が無いため接続一覧を取得できません"
    agg = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return [], f"接続一覧の取得に失敗: {e}"
    for c in conns:
        e = agg.setdefault(c.pid, {"pid": c.pid, "est": 0, "listen": 0, "udp": 0, "peers": set()})
        if c.type == socket.SOCK_DGRAM:
            e["udp"] += 1
        elif c.status == psutil.CONN_LISTEN:
            e["listen"] += 1
        elif c.status == psutil.CONN_ESTABLISHED:
            e["est"] += 1
        if c.raddr:
            e["peers"].add(c.raddr[0])
    rows = []
    for pid, e in agg.items():
        try:
            name = psutil.Process(pid).name() if pid else "不明 (権限なしでPIDが見えない)"
        except Exception:
            name = f"pid:{pid}"
        rows.append({"proc": name, "pid": pid or 0, "est": e["est"], "listen": e["listen"],
                     "udp": e["udp"], "peers": len(e["peers"])})
    rows.sort(key=lambda r: (r["est"], r["peers"], r["udp"]), reverse=True)
    return rows[:limit], None


# ---------- タブ本体 ----------

CONN_COLUMNS = [("proc", "プロセス", 210), ("pid", "PID", 70), ("est", "TCP確立", 80),
                ("listen", "LISTEN", 75), ("udp", "UDP", 60), ("peers", "接続先IP数", 90)]

CAPABILITY_NOTE = (
    "取れる: NIC全体の送受信バイト数(psutilの累積カウンタ差分・管理者権限不要・正確)。   "
    "取れない: プロセス別のバイト数 — Windowsは管理者権限なしでは提供しない"
    "(SRUM DBは読み取り不可、ETWは管理者専用)。下表はプロセス別の「接続数」であって通信量ではない。"
)


class BandwidthTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.points = collections.deque(maxlen=MAX_MEM_SAMPLES)  # (t, up, down)
        self.last_per_nic = {}
        self.conn_rows = []
        self.detection = None
        self.error = None
        self.range_s = RANGES[0][1]
        self._interval = DEFAULT_INTERVAL_S
        self._stop = threading.Event()
        self._after_job = None
        self._limit = self._setting("capture.top_limit", 30)

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        self.start_btn = ttk.Button(top, text="▶  記録開始", style="Accent.TButton", command=self.start)
        self.start_btn.grid(row=0, column=0, padx=(0, 4))
        self.stop_btn = ttk.Button(top, text="⏸  停止", command=self.stop)
        self.stop_btn.grid(row=0, column=1, padx=4)
        ttk.Label(top, text="間隔(秒)").grid(row=0, column=2, padx=(12, 4))
        self.interval_var = tk.DoubleVar(value=DEFAULT_INTERVAL_S)
        # tk変数はワーカースレッドから読むと RuntimeError("main thread is not in main loop")
        # になるので、メインスレッド側で素のfloatへ写しておく(実際に踏んだ)
        self.interval_var.trace_add("write", lambda *_: self._sync_interval())
        ttk.Spinbox(top, from_=1.0, to=60.0, increment=1.0, textvariable=self.interval_var,
                    width=5).grid(row=0, column=3)
        ttk.Label(top, text="表示範囲").grid(row=0, column=4, padx=(12, 4))
        self.range_var = tk.StringVar(value=RANGES[0][0])
        combo = ttk.Combobox(top, textvariable=self.range_var, values=[r[0] for r in RANGES],
                             state="readonly", width=13)
        combo.grid(row=0, column=5)
        combo.bind("<<ComboboxSelected>>", self._on_range)
        ttk.Button(top, text="↻  経路/VPN再検査", command=self.detect).grid(row=0, column=6, padx=(12, 4))
        ttk.Button(top, text="⬇  JSON", command=lambda: self.export("json")).grid(row=0, column=7, padx=4)
        ttk.Button(top, text="⬇  CSV", command=lambda: self.export("csv")).grid(row=0, column=8, padx=4)

        self.note = ttk.Label(parent, text=CAPABILITY_NOTE, wraplength=1150,
                              justify="left", padding=(6, 2, 6, 4))
        self.note.pack(fill="x")
        self.status = ttk.Label(parent, text="準備中", padding=(6, 2))
        self.status.pack(fill="x")

        self.canvas = tk.Canvas(parent, height=240, highlightthickness=1, bd=0)
        self.canvas.pack(fill="both", expand=True, padx=4, pady=(2, 2))
        self.canvas.bind("<Configure>", lambda e: self.draw())

        self.peak_label = ttk.Label(parent, text="ピーク: -", padding=(6, 2))
        self.peak_label.pack(fill="x")

        lower = ttk.Frame(parent)
        lower.pack(fill="both", expand=True, padx=4, pady=(2, 8))
        left = ttk.Frame(lower)
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="プロセス別の接続数 (通信量ではない)").pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=[c[0] for c in CONN_COLUMNS], show="headings", height=9)
        for key, head, width in CONN_COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width, anchor="w" if key == "proc" else "e",
                             stretch=key == "proc")
        self.tree.pack(fill="both", expand=True)

        right = ttk.Frame(lower)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        ttk.Label(right, text="経路 / VPN / プロキシ").pack(anchor="w")
        self.detail = tk.Text(right, height=9, wrap="word", state="disabled",
                              relief="flat", padx=8, pady=6)
        self.detail.pack(fill="both", expand=True)

        self.on_theme_changed()
        self.points.extend((r["t"], r["up"], r["down"]) for r in read_jsonl_tail(jsonl_path()))
        self.start()
        self.detect()

    # ---- 補助 ----

    @staticmethod
    def _setting(dotted, fallback):
        try:
            from settings_store import settings
            v = settings.get(dotted)
            return fallback if v is None else v
        except Exception:
            return fallback

    def _sync_interval(self):
        try:
            self._interval = max(1.0, float(self.interval_var.get()))
        except (tk.TclError, ValueError):
            pass  # Spinbox の途中入力(空文字など)は無視して前の値を使う

    def _ui(self, fn, *args):
        """ワーカースレッドからUIを触る唯一の経路。mainloop 終了後の after は
        RuntimeError / TclError になるので握り潰す(実際に踏んだ)。"""
        try:
            self.ctx.root.after(0, lambda: fn(*args))
        except (RuntimeError, tk.TclError):
            pass

    @property
    def _running(self):
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    _thread = None

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        self.canvas.config(bg=t["graph_bg"], highlightbackground=t["graph_grid"])
        self.detail.config(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"],
                           font=(self.ctx.font, 9), highlightbackground=t["graph_grid"])
        for tag, color in (("head", t["fg"]), ("good", t["good"]), ("warn", t["warn"]),
                           ("bad", t["bad"]), ("muted", t["muted"])):
            self.detail.tag_configure(tag, foreground=color, lmargin2=16)  # 折り返し行をぶら下げる
        self.detail.tag_configure("head", font=(self.ctx.font, 9, "bold"))
        for tag in ("good", "warn", "bad"):
            self.tree.tag_configure(tag, foreground=t[tag])
        # sv_ttk が style map に -foreground を入れており、そのままだと行タグの色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる (pathmon_tab.py と同じ対処)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.note.config(foreground=t["muted"])
        self.status.config(foreground=t["bad"] if self.error else t["muted"])
        self.peak_label.config(foreground=t["muted"])
        self._render_detection(self.detection)
        self.draw()

    # ---- 制御 ----

    def start(self):
        if psutil is None:
            self.error = "psutil が見つからないため帯域を記録できません"
            self._refresh(schedule=False)
            return
        if self._running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._refresh()

    def stop(self):
        self._stop.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self._after_job:
            try:
                self.ctx.root.after_cancel(self._after_job)
            except (RuntimeError, tk.TclError):
                pass
            self._after_job = None
        self._refresh(schedule=False)

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _on_range(self, _event=None):
        self.range_s = dict((n, s) for n, s in RANGES).get(self.range_var.get(), 300)
        self.draw()

    # ---- 記録ワーカー ----

    def _loop(self):
        prev = counter_snapshot()
        prev_t = time.monotonic()
        path = jsonl_path()
        n = 0
        while not self._stop.is_set():
            self._stop.wait(self._interval)
            if self._stop.is_set():
                break
            try:
                cur = counter_snapshot()
                now_m = time.monotonic()
                up, down, per_nic = diff_counters(prev, cur, now_m - prev_t)
                prev, prev_t = cur, now_m
                if not per_nic:      # 起動直後や全NICがラップした区間。記録しない
                    continue
                ts = time.time()
                self.points.append((ts, up, down))
                self.last_per_nic = per_nic
                append_jsonl(path, {"t": round(ts, 1), "up": round(up, 1), "down": round(down, 1),
                                    "nics": {k: [round(v[0], 1), round(v[1], 1)]
                                             for k, v in per_nic.items()}})
                n += 1
                if n % CONN_REFRESH_EVERY == 1:
                    rows, err = collect_connections(self._limit)
                    self.conn_rows = rows
                    self.error = err
            except Exception as e:  # 1サンプルの失敗で記録を止めない
                self.error = f"記録中のエラー: {e}"

    def detect(self):
        threading.Thread(target=self._detect_worker, daemon=True).start()

    def _detect_worker(self):
        det = {"error": None}
        try:
            det["adapters"] = collect_adapters()
            det["routes"] = collect_routes()
            det["proxy"] = collect_proxy()
            try:
                det["local_ip"] = tm.get_local_ipv4()
            except OSError as e:
                det["local_ip"], det["error"] = None, f"外向きソケットを作れません: {e}"
            det["local_nic"] = nic_of_ip(det.get("local_ip"))
            hit = next((a for a in det["adapters"] if a["name"] == det.get("local_nic")), None)
            det["local_nic_info"] = hit
            det["public"] = nd.lookup_ip_info()
            det["checked_at"] = datetime.now().isoformat(timespec="seconds")
        except Exception as e:
            det["error"] = f"検査に失敗: {e}"
        self.detection = det
        self._ui(self._render_detection, det)

    # ---- 表示 ----

    def _visible(self):
        pts = list(self.points)
        if self.range_s and pts:
            cutoff = time.time() - self.range_s
            pts = [p for p in pts if p[0] >= cutoff]
        return pts

    def _refresh(self, schedule=True):
        t = self.ctx.theme
        pts = self._visible()
        s = summarize(pts)
        if self.error:
            self.status.config(text=self.error, foreground=t["bad"])
        elif self._running:
            last = pts[-1] if pts else None
            live = (f"↓ {fmt_bps(last[2])} ({fmt_mbps(last[2])})   ↑ {fmt_bps(last[1])} "
                    f"({fmt_mbps(last[1])})") if last else "初回サンプル待ち"
            self.status.config(text=f"記録中  {live}   /  表示 {s['count']} 点  "
                                    f"(保持 {len(self.points)} 点、ファイルには全件)",
                               foreground=t["muted"])
        else:
            self.status.config(text=f"停止中  ({len(self.points)} 点を保持)", foreground=t["muted"])

        if s["peak_down"] and s["peak_up"]:
            pd_t, pd_v = s["peak_down"]
            pu_t, pu_v = s["peak_up"]
            self.peak_label.config(
                text=f"ピーク  ↓ {fmt_bps(pd_v)} ({fmt_mbps(pd_v)}) @ "
                     f"{datetime.fromtimestamp(pd_t):%m/%d %H:%M:%S}    "
                     f"↑ {fmt_bps(pu_v)} ({fmt_mbps(pu_v)}) @ "
                     f"{datetime.fromtimestamp(pu_t):%m/%d %H:%M:%S}    "
                     f"平均 ↓ {fmt_bps(s['avg_down'])} / ↑ {fmt_bps(s['avg_up'])}")
        else:
            self.peak_label.config(text="ピーク: - (データなし)")

        rows = list(self.conn_rows)
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            tag = "good" if r["est"] else ("warn" if r["udp"] else "")
            self.tree.insert("", "end", values=(r["proc"], r["pid"], r["est"], r["listen"],
                                                r["udp"], r["peers"]), tags=(tag,) if tag else ())
        self.draw()

        if schedule and self._running:
            try:
                self._after_job = self.ctx.root.after(1000, self._refresh)
            except (RuntimeError, tk.TclError):
                self._after_job = None

    # ---- グラフ ----

    def draw(self):
        c = self.canvas
        c.delete("all")
        t = self.ctx.theme
        w, h = c.winfo_width(), c.winfo_height()
        if w <= 1:   # 初回の <Configure> 前は 1 が返る
            w = 1100
        if h <= 1:
            h = 240
        x0, x1, y0, y1 = 70, w - 12, 16, h - 22
        if x1 <= x0 + 10 or y1 <= y0 + 10:
            return

        pts = self._visible()
        if not pts:
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2, fill=t["muted"], font=(self.ctx.font, 10),
                          text="まだ記録がありません (記録開始から数秒で最初の点が出ます)")
            return

        now = time.time()
        span = self.range_s or max(now - pts[0][0], 60)
        t0, t1 = now - span, now
        vmax = nice_ceil(max(max(p[1], p[2]) for p in pts))

        for i in range(5):  # 横の目盛
            v = vmax * i / 4
            y = scale(v, 0, vmax, y1, y0)
            c.create_line(x0, y, x1, y, fill=t["graph_grid"])
            c.create_text(x0 - 6, y, text=fmt_bps(v), anchor="e", fill=t["muted"],
                          font=(self.ctx.font, 8))
        fmt = "%H:%M" if span > 900 else "%H:%M:%S"
        for i in range(5):  # 縦の目盛
            tt = t0 + span * i / 4
            x = scale(tt, t0, t1, x0, x1)
            c.create_line(x, y0, x, y1, fill=t["graph_grid"])
            c.create_text(x, y1 + 11, text=datetime.fromtimestamp(tt).strftime(fmt),
                          fill=t["muted"], font=(self.ctx.font, 8))

        cols = bucket_by_pixel(pts, t0, t1, x0, x1)
        for idx, color, label in ((1, DOWN_COLOR, "受信"), (2, UP_COLOR, "送信")):
            coords = []
            for x, up, down in cols:
                coords += [x, scale(down if idx == 1 else up, 0, vmax, y1, y0)]
            if len(coords) >= 4:
                c.create_line(*coords, fill=color, width=2, smooth=False)
            elif coords:  # 1点しか無いとき
                c.create_oval(coords[0] - 3, coords[1] - 3, coords[0] + 3, coords[1] + 3,
                              fill=color, outline=color)

        s = summarize(pts)
        for (pt, pv), color, mark in ((s["peak_down"], DOWN_COLOR, "↓"), (s["peak_up"], UP_COLOR, "↑")):
            if pv <= 0:
                continue
            px = scale(pt, t0, t1, x0, x1)
            py = scale(pv, 0, vmax, y1, y0)
            c.create_oval(px - 4, py - 4, px + 4, py + 4, outline=color, fill=t["graph_bg"], width=2)
            c.create_text(min(px + 8, x1 - 4), max(py - 10, y0 + 6), anchor="e" if px > x1 - 90 else "w",
                          text=f"{mark}ピーク {fmt_bps(pv)}", fill=color, font=(self.ctx.font, 8))

        lx = x0 + 8
        for color, label in ((DOWN_COLOR, "受信 (下り)"), (UP_COLOR, "送信 (上り)")):
            c.create_line(lx, y0 + 4, lx + 16, y0 + 4, fill=color, width=3)
            c.create_text(lx + 20, y0 + 4, text=label, anchor="w", fill=t["muted"],
                          font=(self.ctx.font, 8))
            lx += 110

    # ---- 検出結果の表示 ----

    def _render_detection(self, det):
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")

        def line(text, tag="muted"):
            self.detail.insert("end", text + "\n", tag)

        if not det:
            line("検査中...")
            self.detail.config(state="disabled")
            return
        if det.get("error"):
            line(det["error"], "bad")

        adapters = det.get("adapters") or []
        virtual = [a for a in adapters if a["category"]]
        vpn_named = [a for a in virtual if a["vpn_like"]]
        proxy = det.get("proxy") or {}
        local_nic_info = det.get("local_nic_info")

        line("【検出したもの (事実)】", "head")
        line(f"  アダプタ {len(adapters)} 個 / うち仮想と判定 {len(virtual)} 個 "
             f"/ うち名前がVPN系 {len(vpn_named)} 個")
        for a in virtual or []:
            line(f"    ・{a['name']}  [{a['desc']}]  {a['status']}  → {a['category']}",
                 "warn" if a["vpn_like"] else "muted")
        for r in (det.get("routes") or []):
            line(f"  既定経路: {r.get('InterfaceAlias')} (ifIndex {r.get('ifIndex')}) "
                 f"→ {r.get('NextHop')}  metric {r.get('RouteMetric')}/{r.get('InterfaceMetric')}")
        line(f"  実際の送出元: {det.get('local_ip') or '不明'}  "
             f"(NIC: {det.get('local_nic') or '不明'})"
             + (f" → {local_nic_info['category']}" if local_nic_info and local_nic_info["category"] else ""))
        line(f"  システムプロキシ: " + (f"有効 {proxy.get('server')}" if proxy.get("enabled") else "無効"))
        line(f"  自動構成(PAC): {proxy.get('pac') or 'なし'}")
        line(f"  環境変数: " + (", ".join(f"{k}={v}" for k, v in proxy["env"].items())
                              if proxy.get("env") else "なし"))
        pub = det.get("public")
        line(f"  公開IP: {pub['ip']}  {pub.get('org') or ''} "
             f"{pub.get('city') or ''} {pub.get('country') or ''}" if pub else "  公開IP: 取得できず")

        line("")
        line("【そこから言えること (解釈)】", "head")
        if not virtual:
            line("  ・仮想NICは見つからない。VPN/仮想化のアダプタは入っていない。", "good")
        else:
            line("  ・仮想NICがあること自体はVPN利用の証拠ではない "
                 "(Hyper-V/WSL/Docker/Bluetooth等でも作られる)。", "warn")
            if vpn_named:
                line(f"  ・名前がVPN系のアダプタが {len(vpn_named)} 個ある。ただし判定は名前一致だけで、"
                     "接続中かどうかまでは見ていない。", "warn")
        if local_nic_info and local_nic_info["vpn_like"]:
            line("  ・外向き通信の送出元IPがVPN系の仮想NICのもの。この経路は実際にVPN経由の可能性が高い。", "bad")
        elif local_nic_info and local_nic_info["category"]:
            line(f"  ・送出元NICは仮想({local_nic_info['category']})だが、VPN系の名前ではない。", "warn")
        elif det.get("local_ip"):
            line("  ・外向き通信は物理NICから直接出ている。OSレベルのVPNは経路に入っていない。", "good")
        if proxy.get("active"):
            line("  ・プロキシ設定がある。ただし従うかどうかはアプリ次第で、"
                 "全通信がプロキシ経由とは限らない。", "warn")
        else:
            line("  ・システム/環境変数のプロキシ設定は無い。", "good")
        line("  ・公開IPがどこの組織かはここでは判定しない。上の org を見て自分のISPかどうか判断すること。")
        line("  ・アプリ内蔵のプロキシ(ブラウザ拡張・SOCKS)やDNSレベルの迂回はこの検査では見えない。")
        self.detail.config(state="disabled")

    # ---- エクスポート ----

    def export(self, fmt):
        pts = self._visible()
        if not pts:
            self.status.config(text="エクスポートするデータがありません", foreground=self.ctx.theme["warn"])
            return
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "csv":
            path = nd.RESULTS_DIR / f"bandwidth_{stamp}.csv"
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["時刻", "受信バイト毎秒", "送信バイト毎秒", "受信Mbps", "送信Mbps"])
                for t, up, down in pts:
                    w.writerow([datetime.fromtimestamp(t).isoformat(timespec="seconds"),
                                round(down, 1), round(up, 1),
                                round(down * 8 / 1e6, 3), round(up * 8 / 1e6, 3)])
        else:
            path = nd.RESULTS_DIR / f"bandwidth_{stamp}.json"
            s = summarize(pts)
            path.write_text(json.dumps({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "range_label": self.range_var.get(),
                "note": CAPABILITY_NOTE,
                "summary": s,
                "per_nic_latest": self.last_per_nic,
                "connections_per_process": self.conn_rows,
                "detection": self.detection,
                "samples": [{"t": round(t, 1), "up": round(u, 1), "down": round(d, 1)}
                            for t, u, d in pts],
            }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        self.status.config(text=f"✓ 出力: {path.name}", foreground=self.ctx.theme["good"])


# ---------- 自己テスト ----------

def _selftest():
    import tempfile
    from pathlib import Path

    # --- 差分からのスループット算出 ---
    prev = {"eth": (1000, 2000), "wifi": (0, 0)}
    cur = {"eth": (3000, 6000), "wifi": (0, 500)}
    up, down, per = diff_counters(prev, cur, 2.0)
    assert per["eth"] == (1000.0, 2000.0), per
    assert per["wifi"] == (0.0, 250.0), per
    assert (up, down) == (1000.0, 2250.0), (up, down)

    # NIC が追加された(prevに無い) -> 基準が無いので捨てる
    up, down, per = diff_counters({"eth": (0, 0)}, {"eth": (100, 100), "new": (9999, 9999)}, 1.0)
    assert "new" not in per and per["eth"] == (100.0, 100.0), per
    assert (up, down) == (100.0, 100.0), (up, down)

    # NIC が消えた -> 残ったNICだけで計算できる
    up, down, per = diff_counters({"eth": (0, 0), "gone": (5, 5)}, {"eth": (10, 20)}, 1.0)
    assert per == {"eth": (10.0, 20.0)} and (up, down) == (10.0, 20.0), (per, up, down)

    # ラップアラウンド / カウンタリセット -> その区間は捨てる (偽の巨大ピークを作らない)
    up, down, per = diff_counters({"eth": (4_294_967_000, 100)}, {"eth": (500, 200)}, 1.0)
    assert per == {} and (up, down) == (0.0, 0.0), (per, up, down)
    # 片方だけ減っていても、そのNICは丸ごと捨てる
    _, _, per = diff_counters({"a": (100, 100)}, {"a": (200, 50)}, 1.0)
    assert per == {}, per
    # dt が 0 / 負 でもゼロ除算しない
    assert diff_counters(prev, cur, 0) == (0.0, 0.0, {})
    assert diff_counters(prev, cur, -1) == (0.0, 0.0, {})
    # 空入力
    assert diff_counters({}, {}, 1.0) == (0.0, 0.0, {})

    # --- 座標変換 ---
    assert scale(0, 0, 10, 100, 0) == 100
    assert scale(10, 0, 10, 100, 0) == 0
    assert scale(5, 0, 10, 100, 0) == 50
    assert scale(5, 5, 5, 0, 100) == 50.0, "値域が潰れたら中央"
    assert scale(0, 0, 100, 70, 1000) == 70
    assert nice_ceil(0) == 1.0 and nice_ceil(None) == 1.0 and nice_ceil(-5) == 1.0
    assert nice_ceil(0.4) == 0.5, nice_ceil(0.4)
    assert nice_ceil(1) == 1.0 and nice_ceil(1.1) == 2.0 and nice_ceil(3) == 5.0
    assert nice_ceil(11) == 20.0 and nice_ceil(120_000) == 200_000.0, nice_ceil(120_000)

    # 1px へ潰す: ピークは最大値で残る / x昇順
    cols = bucket_by_pixel([(0, 1, 1), (0.001, 99, 2), (10, 3, 3)], 0, 10, 0, 100)
    assert cols[0][0] == 0 and cols[0][1] == 99, cols
    assert cols[-1][0] == 100, cols
    assert [c[0] for c in cols] == sorted(c[0] for c in cols)
    assert bucket_by_pixel([], 0, 10, 0, 100) == []
    assert len(bucket_by_pixel([(1, 1, 1)], 0, 10, 0, 100)) == 1

    # --- 0件/1件の退化ケース ---
    z = summarize([])
    assert z["count"] == 0 and z["peak_up"] is None and z["avg_down"] == 0.0, z
    one = summarize([(100.0, 5.0, 7.0)])
    assert one["count"] == 1 and one["peak_down"] == (100.0, 7.0) and one["avg_up"] == 5.0, one
    two = summarize([(1.0, 5.0, 1.0), (2.0, 1.0, 9.0)])
    assert two["peak_up"] == (1.0, 5.0) and two["peak_down"] == (2.0, 9.0), two
    assert two["avg_up"] == 3.0 and two["start"] == 1.0 and two["end"] == 2.0, two

    # --- JSONL 読み書き (壊れた行は飛ばす) ---
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bandwidth.jsonl"
        assert read_jsonl_tail(p) == [], "存在しないファイルは空"
        append_jsonl(p, {"t": 1.0, "up": 2.0, "down": 3.0, "nics": {"eth": [2.0, 3.0]}})
        with open(p, "a", encoding="utf-8") as f:
            f.write("これは壊れた行\n")
            f.write('{"t": 2.0, "up": 1.0}\n')        # down が無い
            f.write('{"t": "x", "up": 1, "down": 1}\n')  # t が文字列
            f.write('[1,2,3]\n')                       # dict ではない
            f.write("\n")                              # 空行
            f.write('{"t": true, "up": 1, "down": 1}\n')  # bool は数値扱いしない
        append_jsonl(p, {"t": 3.0, "up": 4.0, "down": 5.0})
        recs = read_jsonl_tail(p)
        assert [r["t"] for r in recs] == [1.0, 3.0], recs
        assert recs[0]["nics"] == {"eth": [2.0, 3.0]}, recs[0]
        # maxlen で末尾だけ読む
        for i in range(10):
            append_jsonl(p, {"t": 100.0 + i, "up": 0, "down": 0})
        tail = read_jsonl_tail(p, maxlen=3)
        assert [r["t"] for r in tail] == [107.0, 108.0, 109.0], tail

    # --- 仮想NIC判定 ---
    assert classify_adapter("イーサネット", "Realtek Gaming 2.5GbE Family Controller") is None
    assert classify_adapter("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz") is None
    for name, desc, vpn in [
        ("Tailscale", "Tailscale Tunnel", True),
        ("wg0", "WireGuard Tunnel", True),
        ("ローカル エリア接続", "TAP-Windows Adapter V9", True),
        ("OpenVPN Wintun", "OpenVPN Data Channel Offload", True),
        ("ZeroTier One [abc]", "ZeroTier Virtual Port", True),
        ("イーサネット 2", "NordLynx Tunnel", True),
        ("Ethernet 3", "Cisco AnyConnect Secure Mobility Client Virtual Miniport", True),
        ("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", False),
        ("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", False),
        ("VirtualBox Host-Only Network", "VirtualBox Host-Only Ethernet Adapter", False),
        ("Teredo Tunneling Pseudo-Interface", "", False),
    ]:
        hit = classify_adapter(name, desc)
        assert hit is not None, (name, desc)
        assert hit[1] is vpn, (name, desc, hit)
    # Hyper-V が先に当たり「VPN(汎用トンネル)」に化けないこと
    assert classify_adapter("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter")[0].startswith("仮想化")

    # --- プロキシ設定のパース ---
    off = parse_proxy({"ProxyEnable": 0, "ProxyServer": None, "AutoConfigURL": None,
                       "ProxyOverride": "*.local"}, {})
    assert off["enabled"] is False and off["active"] is False and off["bypass"] == "*.local", off
    on = parse_proxy({"ProxyEnable": 1, "ProxyServer": "127.0.0.1:8080"}, {})
    assert on["enabled"] and on["active"] and on["server"] == "127.0.0.1:8080", on
    # ProxyEnable=1 でもサーバが空なら有効とは言えない
    half = parse_proxy({"ProxyEnable": 1, "ProxyServer": ""}, {})
    assert half["enabled"] is False and half["active"] is False, half
    # 値が丸ごと無い / None でも落ちない
    assert parse_proxy({}, {})["active"] is False
    assert parse_proxy(None, None)["active"] is False
    # 文字列の "1" (レジストリ読みの型ゆれ)
    assert parse_proxy({"ProxyEnable": "1", "ProxyServer": "p:3128"}, {})["enabled"] is True
    # PAC だけでも active
    pac = parse_proxy({"ProxyEnable": 0, "AutoConfigURL": "http://x/p.pac"}, {})
    assert pac["enabled"] is False and pac["active"] is True and pac["pac"] == "http://x/p.pac", pac
    # 環境変数
    env = parse_proxy({}, {"https_proxy": "http://127.0.0.1:7890", "NO_PROXY": "localhost", "PATH": "x"})
    assert env["env"] == {"HTTPS_PROXY": "http://127.0.0.1:7890", "NO_PROXY": "localhost"}, env
    assert env["active"] is True, env
    # NO_PROXY だけなら経路が変わるわけではない
    only_no = parse_proxy({}, {"NO_PROXY": "localhost"})
    assert only_no["active"] is False, only_no

    # --- PowerShell の要素1個問題 ---
    assert _json_list('{"a":1}') == [{"a": 1}]
    assert _json_list('[{"a":1},{"a":2}]') == [{"a": 1}, {"a": 2}]
    assert _json_list("") == [] and _json_list(None) == [] and _json_list("壊れたJSON") == []

    # --- 表示フォーマット ---
    assert fmt_bps(0) == "0B/s" and fmt_bps(999) == "999B/s"
    assert fmt_bps(1500) == "1.5KB/s" and fmt_bps(2_500_000) == "2.5MB/s"
    assert fmt_bps(None) == "0B/s"
    assert fmt_mbps(1_250_000) == "10.00Mbps", fmt_mbps(1_250_000)

    print("bandwidth selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1200x740")
    root.title("帯域の時系列記録 / VPN・プロキシ検出")
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
    tab = BandwidthTab(frame, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
