#!/usr/bin/env python3
"""常時監視タブ。対象ホストをバックグラウンドでpingし続け、「異常が起きた時刻だけ」を
イベント(連続タイムアウト / RTT急増 / 復旧)として記録する。夜だけ遅い・時々切れる、といった
断続的な不調の証拠取り用。

イベントは results/watchdog_YYYYMMDD.jsonl に1行1件で追記する(日付が変わると自動で新ファイル)。
画面のTreeviewは直近MAX_ROWS件だけを保持するが、ファイルには全件残る。
"""
import json
import statistics
import threading
import time
import tkinter as tk
from collections import deque
from datetime import datetime
from tkinter import ttk

import network_diag as nd
from settings_store import setting

MEDIAN_WINDOW = 30   # RTT中央値を取るサンプル数(成功したpingのみ)
MIN_SAMPLES = 10     # 中央値が意味を持つまでに必要な成功サンプル数。これ未満は急増判定をしない
MAX_ROWS = 500       # 画面に残す行数

# 倍率だけで判定すると、中央値2msのゲートウェイでは7msの誤差程度でも「3.5倍」で拾ってしまい、
# 数日回すとログがLANのゆらぎで埋まる。実害の出ない小さな増加を切るための絶対値の下限。
# 体感に合わなければここを調整する(小さくすると敏感、大きくすると鈍感)。
SPIKE_MIN_DELTA_MS = 20

EV_DOWN = "応答なし"
EV_SPIKE = "RTT急増"
EV_RECOVER = "復旧"

GATEWAY_KEYWORD = "gateway"  # 監視対象欄にこう書くとデフォルトゲートウェイに解決する
DEFAULT_HOSTS = "gateway, 1.1.1.1, 8.8.8.8"


class HostWatch:
    """1ホット分の異常検出ステートマシン。ネットワークに触らない純粋ロジック(自己テスト対象)。

    feed(rtt_ms) に測定結果を1件ずつ渡すと、発生したイベントの [(種別, 詳細), ...] を返す。
    タイムアウトは rtt_ms=None。異常が継続している間は再通知しない(閾値を跨いだ瞬間だけ出す)。
    """

    def __init__(self, fail_streak=3, spike_factor=3.0, window=MEDIAN_WINDOW):
        self.fail_streak = fail_streak
        self.spike_factor = spike_factor
        self.rtts = deque(maxlen=window)
        self.timeouts = 0
        self.down = False
        self.spiking = False

    def feed(self, rtt_ms):
        if rtt_ms is None:
            self.timeouts += 1
            if self.timeouts >= self.fail_streak and not self.down:
                self.down = True
                return [(EV_DOWN, f"{self.timeouts}回連続でタイムアウト")]
            return []

        events = []
        recovered = False
        if self.down:
            events.append((EV_RECOVER, f"{self.timeouts}回連続タイムアウト後に応答再開 ({rtt_ms}ms)"))
            self.down = False
            recovered = True
        self.timeouts = 0

        median = statistics.median(self.rtts) if len(self.rtts) >= MIN_SAMPLES else None
        if median and not recovered:
            is_spike = rtt_ms > median * self.spike_factor and rtt_ms - median >= setting("watchdog.spike_min_delta_ms", SPIKE_MIN_DELTA_MS)
            if is_spike and not self.spiking:
                self.spiking = True
                events.append((EV_SPIKE, f"{rtt_ms}ms (直近中央値 {median:.0f}ms の {rtt_ms / median:.1f}倍)"))
            elif not is_spike and self.spiking:
                self.spiking = False
                events.append((EV_RECOVER, f"RTTが正常化 {rtt_ms}ms (中央値 {median:.0f}ms)"))

        # 急増が続いている間はサンプルに混ぜない。混ぜると中央値が高いほうへ引きずられ、
        # 遅いままなのに「正常化」と誤判定してしまう(夜だけ遅い、が記録できなくなる)。
        if not self.spiking:
            self.rtts.append(rtt_ms)
        return events


def log_path():
    return nd.RESULTS_DIR / f"watchdog_{datetime.now().strftime('%Y%m%d')}.jsonl"


def format_uptime(seconds):
    s = int(seconds)
    return f"{s // 3600}:{s // 60 % 60:02d}:{s % 60:02d}"


class WatchdogTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.stop_event = threading.Event()
        self.stop_event.set()
        self.file_lock = threading.Lock()
        self.event_count = 0
        self.started_at = None
        self.tick_job = None
        self._build(parent)
        self.on_theme_changed()

    # ---------- UI ----------

    def _build(self, parent):
        font = self.ctx.font

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        ttk.Label(top, text="監視対象 (カンマ区切り)").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.hosts_var = tk.StringVar(value=DEFAULT_HOSTS)
        self.hosts_entry = ttk.Entry(top, textvariable=self.hosts_var, width=40)
        self.hosts_entry.grid(row=0, column=1, columnspan=5, sticky="we", padx=(0, 6))
        top.columnconfigure(5, weight=1)

        ttk.Label(top, text="連続タイムアウト回数").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.streak_var = tk.IntVar(value=setting("watchdog.timeout_streak", 3))
        ttk.Spinbox(top, from_=1, to=20, textvariable=self.streak_var, width=5).grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Label(top, text="RTT急増の倍率").grid(row=1, column=2, sticky="w", padx=(12, 6), pady=(8, 0))
        self.factor_var = tk.DoubleVar(value=setting("watchdog.spike_factor", 3.0))
        ttk.Spinbox(top, from_=1.5, to=20.0, increment=0.5, textvariable=self.factor_var, width=6).grid(row=1, column=3, sticky="w", pady=(8, 0))
        ttk.Label(top, text="ping間隔(秒)").grid(row=1, column=4, sticky="w", padx=(12, 6), pady=(8, 0))
        self.interval_var = tk.DoubleVar(value=setting("watchdog.interval_s", 5.0))
        ttk.Spinbox(top, from_=1.0, to=300.0, increment=1.0, textvariable=self.interval_var, width=6).grid(row=1, column=5, sticky="w", pady=(8, 0))

        controls = ttk.Frame(parent, padding=(4, 10, 4, 4))
        controls.pack(fill="x")
        self.start_btn = ttk.Button(controls, text="▶  監視開始", style="Accent.TButton", command=self.start)
        self.start_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(controls, text="⏸  停止", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 6))
        ttk.Button(controls, text="🧹  ログをクリア", command=self.clear_log).pack(side="left", padx=(0, 6))
        self.status_label = ttk.Label(controls, text="", font=(font, 9))
        self.status_label.pack(side="left", padx=12)

        self.summary_label = ttk.Label(parent, text="", font=(font, 10, "bold"), padding=(6, 2))
        self.summary_label.pack(fill="x")

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(4, 8))
        columns = ("time", "target", "kind", "detail")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col, head, width in zip(columns, ["発生時刻", "対象", "種別", "詳細"], [150, 140, 90, 420]):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self._update_summary()

    def on_theme_changed(self):
        t = self.ctx.theme
        self.tree.tag_configure(EV_DOWN, foreground=t["bad"])
        self.tree.tag_configure(EV_SPIKE, foreground=t["warn"])
        self.tree.tag_configure(EV_RECOVER, foreground=t["good"])
        self.summary_label.config(foreground=t["fg"])
        self.status_label.config(foreground=t["muted"] if not self._running else t["good"])

    @property
    def _running(self):
        return not self.stop_event.is_set()

    # ---------- 監視 ----------

    def start(self):
        if self._running:
            return
        hosts = [h.strip() for h in self.hosts_var.get().split(",") if h.strip()]
        if not hosts:
            self.status_label.config(text="監視対象が空です", foreground=self.ctx.theme["bad"])
            return
        try:
            streak, factor, interval = self.streak_var.get(), self.factor_var.get(), self.interval_var.get()
        except tk.TclError:
            self.status_label.config(text="設定値が不正です", foreground=self.ctx.theme["bad"])
            return

        self.stop_event = threading.Event()  # 停止直後の再開で古いワーカーが復活しないよう毎回作り直す
        self.started_at = time.time()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="ゲートウェイ検出中...", foreground=self.ctx.theme["muted"])
        threading.Thread(target=self._launch, args=(hosts, streak, factor, interval, self.stop_event), daemon=True).start()
        self._tick()

    def _launch(self, hosts, streak, factor, interval, stop):
        """ゲートウェイ解決(PowerShell呼び出しで1秒ほどブロックする)を挟んでからワーカーを起こす。"""
        resolved = []
        for h in hosts:
            if h.lower() == GATEWAY_KEYWORD:
                gw = nd.get_default_gateway()
                if gw:
                    resolved.append((f"ゲートウェイ({gw})", gw))
            else:
                resolved.append((h, h))
        if stop.is_set():
            return
        if not resolved:
            self.ctx.root.after(0, lambda: (self.status_label.config(
                text="監視対象を解決できませんでした", foreground=self.ctx.theme["bad"]), self.stop()))
            return
        for name, host in resolved:
            threading.Thread(target=self._worker, args=(name, host, streak, factor, interval, stop), daemon=True).start()
        names = " / ".join(n for n, _ in resolved)
        self.ctx.root.after(0, lambda: self.status_label.config(
            text=f"監視中: {names}", foreground=self.ctx.theme["good"]))

    def _worker(self, name, host, streak, factor, interval, stop):
        state = HostWatch(streak, factor)
        while not stop.is_set():
            t0 = time.perf_counter()
            result = nd.measure_latency(host, count=1, timeout_ms=1000)
            for kind, detail in state.feed(result.get("avg_ms")):
                self._emit(name, kind, detail)
            stop.wait(max(0.0, interval - (time.perf_counter() - t0)))

    def _emit(self, target, kind, detail):
        event = {"time": datetime.now().isoformat(timespec="seconds"),
                 "target": target, "type": kind, "detail": detail}
        try:
            nd.RESULTS_DIR.mkdir(exist_ok=True)
            with self.file_lock, open(log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as e:
            event["detail"] += f"  ※ログ書き込み失敗: {e}"
        self.ctx.root.after(0, self._add_row, event)

    def _add_row(self, event):
        self.event_count += 1
        self.tree.insert("", 0, values=(event["time"].replace("T", " "), event["target"],
                                        event["type"], event["detail"]), tags=(event["type"],))
        children = self.tree.get_children()
        if len(children) > MAX_ROWS:
            self.tree.delete(*children[MAX_ROWS:])
        self._update_summary()

    def _tick(self):
        self._update_summary()
        if self._running:
            self.tick_job = self.ctx.root.after(1000, self._tick)

    def _update_summary(self):
        uptime = format_uptime(time.time() - self.started_at) if self.started_at and self._running else "-"
        self.summary_label.config(
            text=f"稼働時間 {uptime}   総イベント数 {self.event_count}   ログ: {log_path().name}"
                 f"   (画面表示は直近{MAX_ROWS}件、ファイルには全件)")

    def stop(self):
        self.stop_event.set()
        if self.tick_job:
            self.ctx.root.after_cancel(self.tick_job)
            self.tick_job = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="停止中", foreground=self.ctx.theme["muted"])
        self._update_summary()

    def clear_log(self):
        """画面の一覧だけを消す。JSONLファイルは証拠なので触らない。"""
        self.tree.delete(*self.tree.get_children())
        self.event_count = 0
        self._update_summary()

    def on_close(self):
        self.stop_event.set()


# ---------- 自己テスト (ネットワーク不要) ----------

def selftest():
    w = HostWatch(fail_streak=3, spike_factor=3.0)
    for _ in range(MIN_SAMPLES):
        assert w.feed(20) == []

    assert w.feed(None) == []
    assert w.feed(None) == []
    ev = w.feed(None)
    assert [k for k, _ in ev] == [EV_DOWN], ev
    assert w.feed(None) == [], "異常継続中に再通知してはいけない"
    ev = w.feed(20)
    assert [k for k, _ in ev] == [EV_RECOVER], ev

    assert w.feed(30) == [], "中央値20の3倍未満なので急増ではない"
    ev = w.feed(100)
    assert [k for k, _ in ev] == [EV_SPIKE], ev
    assert w.feed(120) == [], "急増継続中に再通知してはいけない"
    ev = w.feed(21)
    assert [k for k, _ in ev] == [EV_RECOVER], ev

    # 中央値のサンプルが足りないうちは急増を出さない(起動直後の誤検出防止)
    w2 = HostWatch(3, 3.0)
    for _ in range(MIN_SAMPLES - 1):
        w2.feed(10)
    assert w2.feed(500) == []
    assert [k for k, _ in w2.feed(500)] == [EV_SPIKE]

    # 急増が続いても中央値が引きずられない(遅いままを「正常化」と誤判定しない)
    w3 = HostWatch(3, 3.0)
    for _ in range(MIN_SAMPLES):
        w3.feed(10)
    assert [k for k, _ in w3.feed(200)] == [EV_SPIKE]
    for _ in range(MEDIAN_WINDOW * 2):
        assert w3.feed(200) == []

    # 倍率を超えても増加量が小さければ無視する(LANのゆらぎでログを埋めない)
    w5 = HostWatch(3, 3.0)
    for _ in range(MIN_SAMPLES):
        w5.feed(2)
    assert w5.feed(8) == [], "4倍でも+6msなら急増としない"
    assert [k for k, _ in w5.feed(80)] == [EV_SPIKE]

    # 閾値を変えられること
    w4 = HostWatch(1, 10.0)
    assert [k for k, _ in w4.feed(None)] == [EV_DOWN]
    for _ in range(MIN_SAMPLES):
        w4.feed(10)
    assert w4.feed(50) == [], "10倍設定なので5倍では出ない"
    assert [k for k, _ in w4.feed(150)] == [EV_SPIKE]

    assert format_uptime(3725) == "1:02:05"
    print("watchdog selftest: OK")


if __name__ == "__main__":
    import sys

    selftest()
    if "--selftest" in sys.argv:
        sys.exit(0)

    import sv_ttk

    root = tk.Tk()
    root.geometry("900x600")
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
    tab = WatchdogTab(frame, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
