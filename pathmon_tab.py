#!/usr/bin/env python3
"""経路の常時監視 (MTR風) タブ。TTLを1から増やしながらICMP Echoを投げ続け、
ホップごとの応答元IP・ロス率・RTT統計を表として継続更新する。

計測エンジンに `ping.exe -i <TTL>` ではなく iphlpapi.dll の IcmpSendEcho (ctypes) を使っている理由:
実機計測で subprocess による ping 起動のオーバーヘッドが 28〜35ms あり、
ホップ1(自宅ゲートウェイ)の実RTT 1〜3ms を完全に埋めてしまうため統計として使い物にならなかった。
さらに ping.exe の「TTLが期限切れ」応答行にはそもそもRTTが出力されない
(実測: '192.168.3.1 からの応答: 転送中に TTL が期限切れになりました。')。
IcmpSendEcho は ping.exe 自身が使う同じユーザーランドAPIで、管理者権限不要・応答元IPとRTTを直接返す。
"""
import csv
import ctypes
import ctypes.wintypes as wintypes
import json
import queue
import socket
import statistics
import struct
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import network_diag as nd

DEFAULT_TARGET = "1.1.1.1"
MAX_HOPS = 30
PROBE_TIMEOUT_MS = 1000
INTER_HOP_SLEEP_S = 0.02  # 経路上のルータのICMPレート制限を避けるための小休止
WARN_LOSS_PCT = 5.0

# ---------- Win32 ICMP (iphlpapi.dll) ----------

_IP_SUCCESS = 0
_IP_REQ_TIMED_OUT = 11010
_IP_TTL_EXPIRED_TRANSIT = 11013


class _IpOptionInformation(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.POINTER(ctypes.c_ubyte))]


class _IcmpEchoReply(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                ("Options", _IpOptionInformation)]


_iphlpapi = ctypes.WinDLL("iphlpapi")
_iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
_iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_iphlpapi.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_ushort,
                                   ctypes.POINTER(_IpOptionInformation), ctypes.c_void_p,
                                   ctypes.c_ulong, ctypes.c_ulong]
_iphlpapi.IcmpSendEcho.restype = ctypes.c_ulong

_PAYLOAD = b"pathmon-probe-payload-0123456789"[:32]
_REPLY_BUF_SIZE = ctypes.sizeof(_IcmpEchoReply) + len(_PAYLOAD) + 64


def probe(dest_ip, ttl, timeout_ms=PROBE_TIMEOUT_MS):
    """TTLを指定してICMP Echoを1発送る。-> (応答元IP|None, RTTms|None, 宛先に到達したか)

    RTTは perf_counter による送信〜応答の実測。API の RoundTripTime は整数msで
    LAN内ホップが軒並み0msに丸まるため使わない。呼び出しオーバーヘッド分 +0.5〜0.8ms の
    系統的な上振れがある(実測値: API 3ms / 実測 3.8ms)。
    """
    handle = _iphlpapi.IcmpCreateFile()
    if handle in (0, None) or handle == wintypes.HANDLE(-1).value:
        return None, None, False
    try:
        opt = _IpOptionInformation(ttl, 0, 0, 0, None)
        buf = ctypes.create_string_buffer(_REPLY_BUF_SIZE)
        addr = struct.unpack("<I", socket.inet_aton(dest_ip))[0]
        start = time.perf_counter()
        n = _iphlpapi.IcmpSendEcho(handle, addr, _PAYLOAD, len(_PAYLOAD),
                                   ctypes.byref(opt), buf, _REPLY_BUF_SIZE, timeout_ms)
        elapsed_ms = (time.perf_counter() - start) * 1000
        if not n:  # タイムアウト、または送信自体の失敗
            return None, None, False
        reply = _IcmpEchoReply.from_buffer(buf)
        responder = socket.inet_ntoa(struct.pack("<I", reply.Address)) if reply.Address else None
        return responder, round(elapsed_ms, 1), reply.Status == _IP_SUCCESS
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


# ---------- ホップ統計 ----------

class HopStat:
    def __init__(self, hop):
        self.hop = hop
        self.ips = []  # 出現順。ECMP(等コスト負荷分散)で1ホップが複数IPを返すことがある
        self.sent = 0
        self.recv = 0
        self.rtts = []
        self.last_ms = None

    def record(self, ip, rtt_ms):
        self.sent += 1
        if ip and ip not in self.ips:
            self.ips.append(ip)
        if rtt_ms is None:
            self.last_ms = None
            return
        self.recv += 1
        self.last_ms = rtt_ms
        self.rtts.append(rtt_ms)

    @property
    def ip(self):
        return self.ips[-1] if self.ips else None

    @property
    def loss_pct(self):
        return round((self.sent - self.recv) / self.sent * 100, 1) if self.sent else 0.0

    def summary(self):
        r = self.rtts
        return {
            "hop": self.hop,
            "ip": self.ip,
            "ips": list(self.ips),
            "sent": self.sent,
            "recv": self.recv,
            "loss_pct": self.loss_pct,
            "last_ms": self.last_ms,
            "avg_ms": round(sum(r) / len(r), 1) if r else None,
            "min_ms": min(r) if r else None,
            "max_ms": max(r) if r else None,
            "sdev_ms": round(statistics.pstdev(r), 1) if len(r) > 1 else (0.0 if r else None),
        }


def loss_tag(loss_pct):
    """ロス率 -> Treeviewの色タグ名。0%=good / 〜5%=warn / それ以上=bad"""
    if loss_pct <= 0:
        return "good"
    return "warn" if loss_pct <= WARN_LOSS_PCT else "bad"


# ---------- タブ本体 ----------

COLUMNS = [
    ("hop", "#", 40), ("ip", "IP", 120), ("host", "ホスト名", 190), ("org", "組織名", 210),
    ("sent", "送信", 48), ("recv", "受信", 48), ("loss", "ロス%", 60),
    ("last", "最終", 60), ("avg", "平均", 60), ("min", "最小", 60), ("max", "最大", 60), ("sdev", "標準偏差", 68),
]


class PathMonTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.hops = {}          # ttl -> HopStat
        self.meta = {}          # ip -> {"host": str, "org": str}
        self.dest_ip = None
        self.cycles = 0
        self.error = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._after_job = None
        self._lookup_q = queue.Queue()
        self._lookup_seen = set()
        self._lookup_thread = None

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        ttk.Label(top, text="対象ホスト").grid(row=0, column=0, padx=(0, 6))
        self.target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(top, textvariable=self.target_var, width=22).grid(row=0, column=1, padx=(0, 12))
        ttk.Label(top, text="測定間隔(秒)").grid(row=0, column=2, padx=(0, 6))
        self.interval_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(top, from_=0.5, to=30.0, increment=0.5, textvariable=self.interval_var,
                    width=6).grid(row=0, column=3, padx=(0, 12))
        self.start_btn = ttk.Button(top, text="▶  開始", style="Accent.TButton", command=self.start)
        self.start_btn.grid(row=0, column=4, padx=4)
        self.stop_btn = ttk.Button(top, text="⏸  停止", command=self.stop, state="disabled")
        self.stop_btn.grid(row=0, column=5, padx=4)
        ttk.Button(top, text="↺  リセット", command=self.reset).grid(row=0, column=6, padx=4)
        ttk.Button(top, text="⬇  CSV", command=lambda: self.export("csv")).grid(row=0, column=7, padx=(12, 4))
        ttk.Button(top, text="⬇  JSON", command=lambda: self.export("json")).grid(row=0, column=8, padx=4)

        self.status = ttk.Label(parent, text="停止中", padding=(6, 4))
        self.status.pack(fill="x")

        self.tree = ttk.Treeview(parent, columns=[c[0] for c in COLUMNS], show="headings", height=18)
        for key, head, width in COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width, anchor="w" if key in ("ip", "host", "org") else "e",
                             stretch=key in ("host", "org"))
        self.tree.pack(fill="both", expand=True, padx=4, pady=(4, 8))

        self.on_theme_changed()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        for tag in ("good", "warn", "bad"):
            self.tree.tag_configure(tag, foreground=t[tag])
        # sv_ttk が style map に -foreground を設定しており、そのままだとタグ色が無視される
        # (Tk 8.6.9以降の既知の挙動)。選択時以外の状態指定を外してタグ色を優先させる。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.status.config(foreground=t["bad"] if self.error else t["muted"])

    # ---- 制御 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        host = self.target_var.get().strip() or DEFAULT_TARGET
        try:
            self.dest_ip = socket.gethostbyname(host)
        except OSError as e:
            self.error = f"名前解決に失敗: {host} ({e})"
            self._refresh()
            return
        self.error = None
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(self.dest_ip,), daemon=True)
        self._thread.start()
        if not (self._lookup_thread and self._lookup_thread.is_alive()):
            self._lookup_thread = threading.Thread(target=self._lookup_loop, daemon=True)
            self._lookup_thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._refresh()

    def stop(self):
        self._stop.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self._after_job:
            self.ctx.root.after_cancel(self._after_job)
            self._after_job = None
        self._refresh(schedule=False)

    def reset(self):
        with self._lock:
            self.hops.clear()
            self.cycles = 0
        self.tree.delete(*self.tree.get_children())
        if not self._running:  # 計測中なら既存の定期更新チェーンが拾う(二重スケジュール防止)
            self._refresh(schedule=False)

    def on_close(self):
        self._stop.set()
        self._lookup_q.put(None)
        for th in (self._thread, self._lookup_thread):
            if th:
                th.join(timeout=2)

    @property
    def _running(self):
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    # ---- 計測ワーカー ----

    def _loop(self, dest_ip):
        path_len = MAX_HOPS  # 宛先に到達したホップ番号が分かったらそこまでに切り詰める
        while not self._stop.is_set():
            t0 = time.perf_counter()
            for ttl in range(1, path_len + 1):
                if self._stop.is_set():
                    return
                ip, rtt, reached = probe(dest_ip, ttl)
                with self._lock:
                    self.hops.setdefault(ttl, HopStat(ttl)).record(ip, rtt)
                if ip and ip not in self._lookup_seen:
                    self._lookup_seen.add(ip)
                    self._lookup_q.put(ip)
                if reached:
                    path_len = ttl
                    break
                self._stop.wait(INTER_HOP_SLEEP_S)
            with self._lock:
                self.cycles += 1
            self._stop.wait(max(0.0, self.interval_var.get() - (time.perf_counter() - t0)))

    def _lookup_loop(self):
        """逆引きDNSとipinfo.ioの組織名を裏で引く。計測ループを止めないよう完全に別スレッド。"""
        while True:
            ip = self._lookup_q.get()
            if ip is None:  # on_close() からの終了合図
                return
            try:
                host = socket.gethostbyaddr(ip)[0]
            except OSError:
                host = ""
            info = nd.lookup_ip_info(ip) or {}
            self.meta[ip] = {"host": host, "org": info.get("org") or ""}

    # ---- 表示 ----

    def _snapshot(self):
        with self._lock:
            return [self.hops[k].summary() for k in sorted(self.hops)], self.cycles

    def _refresh(self, schedule=True):
        rows, cycles = self._snapshot()
        existing = set(self.tree.get_children())
        for row in rows:
            meta = self.meta.get(row["ip"] or "", {})
            ip_text = row["ip"] or "???"
            if len(row["ips"]) > 1:
                ip_text += f" (+{len(row['ips']) - 1})"
            values = (
                row["hop"], ip_text, meta.get("host", ""), meta.get("org", ""),
                row["sent"], row["recv"], f"{row['loss_pct']:.1f}",
                *(f"{row[k]:.1f}" if row[k] is not None else "-"
                  for k in ("last_ms", "avg_ms", "min_ms", "max_ms", "sdev_ms")),
            )
            iid = str(row["hop"])
            if iid in existing:
                self.tree.item(iid, values=values, tags=(loss_tag(row["loss_pct"]),))
            else:
                self.tree.insert("", "end", iid=iid, values=values, tags=(loss_tag(row["loss_pct"]),))

        t = self.ctx.theme
        if self.error:
            self.status.config(text=self.error, foreground=t["bad"])
        elif self._running:
            self.status.config(text=f"計測中  {self.target_var.get()} ({self.dest_ip})  "
                                    f"{cycles} 周  /  {len(rows)} ホップ", foreground=t["muted"])
        else:
            self.status.config(text=f"停止中  ({cycles} 周分の統計を保持)" if cycles else "停止中",
                               foreground=t["muted"])

        if schedule and self._running:
            self._after_job = self.ctx.root.after(500, self._refresh)

    # ---- エクスポート ----

    def export(self, fmt):
        rows, cycles = self._snapshot()
        if not rows:
            self.status.config(text="エクスポートするデータがありません", foreground=self.ctx.theme["warn"])
            return
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"pathmon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        for row in rows:
            row.update(self.meta.get(row["ip"] or "", {"host": "", "org": ""}))
        if fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow([c[1] for c in COLUMNS])
                for r in rows:
                    w.writerow([r["hop"], r["ip"] or "", r["host"], r["org"], r["sent"], r["recv"],
                                r["loss_pct"], r["last_ms"], r["avg_ms"], r["min_ms"], r["max_ms"], r["sdev_ms"]])
        else:
            path.write_text(json.dumps({
                "target": self.target_var.get(), "dest_ip": self.dest_ip,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "cycles": cycles, "hops": rows,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        self.status.config(text=f"✓ 出力: {path.name}", foreground=self.ctx.theme["good"])


# ---------- 自己テスト ----------

def _selftest():
    s = HopStat(1)
    for ip, rtt in [("192.168.3.1", 3.0), ("192.168.3.1", 5.0), (None, None), ("192.168.3.1", 4.0)]:
        s.record(ip, rtt)
    r = s.summary()
    assert (r["sent"], r["recv"]) == (4, 3), r
    assert r["loss_pct"] == 25.0, r
    assert (r["min_ms"], r["max_ms"], r["avg_ms"], r["last_ms"]) == (3.0, 5.0, 4.0, 4.0), r
    assert r["sdev_ms"] == 0.8, r  # pstdev([3,5,4]) = 0.8165
    assert r["ip"] == "192.168.3.1" and r["ips"] == ["192.168.3.1"], r

    empty = HopStat(9).summary()
    assert empty["loss_pct"] == 0.0 and empty["avg_ms"] is None and empty["ip"] is None, empty

    ecmp = HopStat(2)
    ecmp.record("10.0.0.1", 1.0)
    ecmp.record("10.0.0.2", 2.0)
    assert ecmp.summary()["ips"] == ["10.0.0.1", "10.0.0.2"]

    lost = HopStat(3)
    lost.record(None, None)
    assert lost.summary()["loss_pct"] == 100.0 and lost.summary()["sdev_ms"] is None

    assert (loss_tag(0.0), loss_tag(0.1), loss_tag(5.0), loss_tag(5.1), loss_tag(100.0)) == \
           ("good", "warn", "warn", "bad", "bad")

    # 実機ICMP: ホップ1は必ずデフォルトゲートウェイが応答するはず
    gw = nd.get_default_gateway()
    ip, rtt, reached = probe("1.1.1.1", 1)
    assert ip is not None and rtt is not None, ("hop1 no reply", ip, rtt)
    assert not reached, "hop1 が宛先扱いになっている"
    if gw:
        assert ip == gw, (ip, gw)
    ip_far, rtt_far, reached_far = probe("1.1.1.1", 30)
    assert reached_far and ip_far == "1.1.1.1", (ip_far, rtt_far, reached_far)
    print(f"selftest: OK (hop1={ip} {rtt}ms / dest={ip_far} {rtt_far}ms)")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        raise SystemExit

    import sv_ttk

    root = tk.Tk()
    root.geometry("1100x600")
    root.title("経路の常時監視 (MTR風)")
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
    tab = PathMonTab(frame, ctx)
    if "--auto" in sys.argv:
        root.after(200, tab.start)
        root.after(12000, lambda: (tab.on_close(), root.destroy()))
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
