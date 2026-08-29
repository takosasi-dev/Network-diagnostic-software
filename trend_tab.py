#!/usr/bin/env python3
"""定期実行 + 時間帯トレンド タブ。

軽量な計測 (RTT/パケロス + 短時間スループット) を一定間隔で自動実行し、
1行1計測の JSONL として results/trend.jsonl に追記する。
蓄積したデータを「時系列」「時間帯別」「曜日×時間帯ヒートマップ」の3ビューで可視化し、
「夜だけ遅い」のような時間帯依存の劣化を目に見える形にするのが目的。

既定の計測秒数 (下り3秒 / 上り3秒) は実測して決めた。この回線での実測:
  2秒: 下り 60〜76MB (236〜296Mbps) / 上り 44〜60MB (163〜227Mbps)
  3秒: 下り 80〜116MB (212〜307Mbps) / 上り 52〜80MB (135〜205Mbps)
  5秒: 下り 164MB (254Mbps) / 上り 112MB (174Mbps)
測定値のばらつきは 2秒で CV 10.5% / 3秒で CV 13.4% (n=5) と有意差が無く、
秒数を延ばしても安定はしない。ばらつきは時間帯ごとの中央値で吸収する前提なので
秒数は「通信量をいくら払うか」で決めればよい。既定は 3秒 (1回約170MB / 30分間隔で約8GB/日)。
従量制回線なら UI の秒数スピンボックスを下げるか、下り/上りのチェックを外す。

RTT は ping 10回で約9秒かかるが通信量は 1KB 未満なので既定でON。
"""
import csv
import json
import math
import statistics
import threading
import time
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import ttk

import network_diag as nd
from settings_store import setting

JSONL_NAME = "trend.jsonl"          # 日付ローテーションしない。時系列として一続きに扱う
RTT_HOST = "1.1.1.1"
RTT_COUNT = 10
MIN_SAMPLES = 3                     # この件数未満の時間帯は「データ不足」扱い
DEFAULT_INTERVAL_MIN = 30
DEFAULT_DURATION_S = 3
NOMINAL_MBPS = {"down": 280.0, "up": 185.0}  # 実測データが貯まるまでの通信量見積り用
RTT_BYTES = 10 * 74 * 2             # ping 10回分の往復 (概算)

DOW_JA = ["月", "火", "水", "木", "金", "土", "日"]
PERIODS = [("直近24時間", 24), ("直近7日", 24 * 7), ("全期間", None)]
# key -> (表示名, テーマ色キー, 大きい方が良いか, 単位)
METRICS = {
    "down_mbps": ("下り", "good", True, "Mbps"),
    "up_mbps": ("上り", "warn", True, "Mbps"),
    "rtt_ms": ("RTT", "bad", False, "ms"),
}


# ---------- 色ユーティリティ ----------

def _hex_to_rgb(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def mix(c1, c2, f):
    """色を f の比で混ぜる (f=0 で c1)。Tk Canvas に透明度が無いので帯の淡色を作るのに使う。"""
    a, b = _hex_to_rgb(c1), _hex_to_rgb(c2)
    return "#%02x%02x%02x" % tuple(max(0, min(255, round(x + (y - x) * f))) for x, y in zip(a, b))


def ramp(colors, frac):
    """色のリストを等間隔に並べたグラデーションから frac (0..1) の位置の色を取る。"""
    frac = max(0.0, min(1.0, frac))
    if len(colors) == 1:
        return colors[0]
    pos = frac * (len(colors) - 1)
    i = min(int(pos), len(colors) - 2)
    return mix(colors[i], colors[i + 1], pos - i)


def readable_on(bg, dark, light):
    """背景色 bg の明度に応じて読める文字色を返す。"""
    r, g, b = _hex_to_rgb(bg)
    return dark if (0.299 * r + 0.587 * g + 0.114 * b) > 140 else light


# ---------- 座標変換 / 目盛 ----------

def scale(v, v0, v1, p0, p1):
    """値域 [v0,v1] を画面座標 [p0,p1] へ線形写像する。v1==v0 なら中央に置く。"""
    if v1 == v0:
        return (p0 + p1) / 2.0
    return p0 + (v - v0) * (p1 - p0) / (v1 - v0)


def nice_ceil(v):
    """軸の上限を切りの良い値へ切り上げる。"""
    if v is None or v <= 0:
        return 1.0
    e = 10.0 ** math.floor(math.log10(v))
    for m in (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if v <= m * e * (1 + 1e-9):
            return m * e
    return 10 * e


def fmt_bytes(n):
    for unit, div in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= div:
            return f"{n / div:.1f}{unit}"
    return f"{n:.0f}B"


# ---------- 永続化 ----------

def jsonl_path():
    return nd.RESULTS_DIR / JSONL_NAME


def load_records(path):
    """JSONL を読む。壊れた行・必須キー欠落・時刻が読めない行は黙って捨てる。-> 時刻昇順のリスト"""
    out = []
    try:
        f = open(path, encoding="utf-8")
    except OSError:
        return out
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(r, dict):
                continue
            try:
                dt = datetime.fromisoformat(r["ts"])
            except (KeyError, TypeError, ValueError):
                continue
            r["_dt"] = dt
            r["hour"] = r.get("hour", dt.hour)
            r["dow"] = r.get("dow", dt.weekday())
            out.append(r)
    out.sort(key=lambda r: r["_dt"])
    return out


def append_record(path, rec):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({k: v for k, v in rec.items() if not k.startswith("_")},
                           ensure_ascii=False) + "\n")


# ---------- 集計 ----------

def _values(records, key):
    for r in records:
        v = r.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            yield r, float(v)


def hourly_stats(records, key):
    """-> {hour: {"n","med","min","max"}}。値が無い計測は無視する。"""
    buckets = {}
    for r, v in _values(records, key):
        buckets.setdefault(int(r["hour"]), []).append(v)
    return {h: {"n": len(vs), "med": statistics.median(vs), "min": min(vs), "max": max(vs)}
            for h, vs in buckets.items()}


def dow_hour_stats(records, key):
    """-> {(dow, hour): {"n","med"}}"""
    buckets = {}
    for r, v in _values(records, key):
        buckets.setdefault((int(r["dow"]), int(r["hour"])), []).append(v)
    return {k: {"n": len(vs), "med": statistics.median(vs)} for k, vs in buckets.items()}


def summarize(hourly, higher_is_better, min_n=MIN_SAMPLES):
    """最良/最悪の時間帯。min_n 件以上ある時間帯が2つ未満なら ok=False (断定しない)。"""
    ok = {h: s for h, s in hourly.items() if s["n"] >= min_n}
    res = {"ok": False, "enough": len(ok), "hours": len(hourly),
           "samples": sum(s["n"] for s in hourly.values()), "min_n": min_n}
    if len(ok) < 2:
        return res
    order = sorted(ok, key=lambda h: ok[h]["med"])
    worst, best = (order[0], order[-1]) if higher_is_better else (order[-1], order[0])
    wv, bv = ok[worst]["med"], ok[best]["med"]
    res.update(ok=True, worst_h=worst, best_h=best, worst=wv, best=bv,
               diff=abs(bv - wv), ratio=(max(wv, bv) / min(wv, bv)) if min(wv, bv) else None)
    return res


def filter_period(records, hours, now=None):
    if not hours:
        return list(records)
    cutoff = (now or datetime.now()) - timedelta(hours=hours)
    return [r for r in records if r["_dt"] >= cutoff]


# ---------- 計測 ----------

def measure_once(do_rtt, do_down, do_up, duration_s, now=None):
    """軽量セットを1回実行して JSONL 1行分の dict を返す。全部OFFなら None。"""
    if not (do_rtt or do_down or do_up):
        return None
    dt = now or datetime.now()
    rec = {"ts": dt.isoformat(timespec="seconds"), "dow": dt.weekday(), "hour": dt.hour,
           "duration_s": duration_s}
    if do_rtt:
        lat = nd.measure_latency(RTT_HOST, count=RTT_COUNT)
        if "error" not in lat:
            rec["rtt_ms"] = lat.get("avg_ms")
            rec["rtt_max_ms"] = lat.get("max_ms")
            rec["loss_pct"] = lat.get("loss_pct")
        else:
            rec["rtt_error"] = lat["error"]
    for on, key, fn in ((do_down, "down", nd.measure_throughput_single),
                        (do_up, "up", nd.measure_upload_single)):
        if not on:
            continue
        r = fn(duration_s=duration_s)
        if "error" in r:
            rec[f"{key}_error"] = r["error"]
        else:
            rec[f"{key}_mbps"] = r["mbps"]
            rec[f"{key}_bytes"] = r["bytes"]
    return rec


def estimate_traffic(records, do_rtt, do_down, do_up, duration_s, interval_min):
    """1回あたり / 1日あたりの推定通信量(バイト)。実測の bytes があればそれを使う。"""
    per = RTT_BYTES if do_rtt else 0
    for on, key in ((do_down, "down"), (do_up, "up")):
        if not on:
            continue
        got = [r[f"{key}_bytes"] / max(r.get("duration_s") or duration_s, 0.1)
               for r in records[-10:] if isinstance(r.get(f"{key}_bytes"), (int, float))]
        rate = statistics.mean(got) if got else NOMINAL_MBPS[key] * 1e6 / 8
        per += rate * duration_s
    return per, per * (1440.0 / max(interval_min, 1))


# ---------- タブ本体 ----------

class TrendTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.path = jsonl_path()
        self.records = load_records(self.path)
        self._stop = threading.Event()
        self._thread = None
        self._tick_job = None
        self._next_at = None
        self._msg = ""
        self._msg_kind = "muted"
        # ワーカースレッドから tk 変数を読まないためのスナップショット
        self.cfg = {"interval": setting("trend.interval_min", DEFAULT_INTERVAL_MIN),
                    "dur": setting("trend.sample_duration_s", DEFAULT_DURATION_S),
                    "rtt": True, "down": True, "up": True}

        # --- 操作列 1: スケジューラ ---
        top = ttk.Frame(parent, padding=(6, 10, 6, 2))
        top.pack(fill="x")
        self.start_btn = ttk.Button(top, text="▶  定期実行を開始", style="Accent.TButton",
                                    command=self.start)
        self.start_btn.pack(side="left", padx=(0, 4))
        self.stop_btn = ttk.Button(top, text="⏸  停止", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(top, text="今すぐ1回", command=self.run_once).pack(side="left", padx=4)
        ttk.Label(top, text="間隔(分)").pack(side="left", padx=(16, 4))
        self.interval_var = tk.IntVar(value=setting("trend.interval_min", DEFAULT_INTERVAL_MIN))
        ttk.Spinbox(top, from_=15, to=360, increment=5, width=5,
                    textvariable=self.interval_var).pack(side="left")
        ttk.Label(top, text="計測秒数").pack(side="left", padx=(12, 4))
        self.dur_var = tk.IntVar(value=setting("trend.sample_duration_s", DEFAULT_DURATION_S))
        ttk.Spinbox(top, from_=1, to=10, increment=1, width=4,
                    textvariable=self.dur_var).pack(side="left")
        self.rtt_var = tk.BooleanVar(value=True)
        self.down_var = tk.BooleanVar(value=True)
        self.up_var = tk.BooleanVar(value=True)
        for text, var in (("RTT+ロス", self.rtt_var), ("下り", self.down_var), ("上り", self.up_var)):
            ttk.Checkbutton(top, text=text, variable=var).pack(side="left", padx=(10, 0))
        ttk.Button(top, text="⬇  CSV", command=self.export_csv).pack(side="right", padx=4)

        # --- 操作列 2: 表示切替 ---
        row2 = ttk.Frame(parent, padding=(6, 4, 6, 2))
        row2.pack(fill="x")
        self.view_var = tk.StringVar(value="hourly")
        for text, val in (("時系列", "series"), ("時間帯別", "hourly"), ("曜日×時間帯", "heatmap")):
            ttk.Radiobutton(row2, text=text, value=val, variable=self.view_var,
                            command=self.refresh).pack(side="left", padx=(0, 10))
        ttk.Separator(row2, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(row2, text="表示期間").pack(side="left", padx=(0, 4))
        self.period_var = tk.StringVar(value=PERIODS[2][0])
        pbox = ttk.Combobox(row2, textvariable=self.period_var, width=11, state="readonly",
                            values=[p[0] for p in PERIODS])
        pbox.pack(side="left")
        ttk.Label(row2, text="ヒートマップ指標").pack(side="left", padx=(16, 4))
        self.metric_var = tk.StringVar(value="down_mbps")
        mbox = ttk.Combobox(row2, textvariable=self.metric_var, width=10, state="readonly",
                            values=list(METRICS))
        mbox.pack(side="left")
        for box in (pbox, mbox):
            box.bind("<<ComboboxSelected>>", lambda e: self.refresh())

        self.status = ttk.Label(parent, text="", padding=(8, 4))
        self.status.pack(fill="x")

        self.canvas = tk.Canvas(parent, width=900, height=380, highlightthickness=1, bd=0)
        self.canvas.pack(fill="both", expand=True, padx=6, pady=(2, 4))
        self.canvas.bind("<Configure>", lambda e: self.draw())

        self.summary = tk.Label(parent, text="", anchor="w", justify="left", padx=10, pady=7,
                                font=(ctx.font, 9))
        self.summary.pack(fill="x", padx=6, pady=(0, 8))

        for var in (self.interval_var, self.dur_var, self.rtt_var, self.down_var, self.up_var):
            var.trace_add("write", lambda *a: self._sync_cfg())
        self._sync_cfg()
        self.on_theme_changed()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        self.canvas.config(bg=t["graph_bg"], highlightbackground=t["graph_grid"])
        self.summary.config(bg=t["card_bg"], fg=t["fg"])
        self._render_status()
        self.draw()

    # ---- 設定 ----

    def _sync_cfg(self):
        """tk 変数 -> プレーンな dict。ワーカースレッドはこちらだけを読む。"""
        def geti(var, lo, hi, dflt):
            try:
                return max(lo, min(hi, int(var.get())))
            except (tk.TclError, ValueError):
                return dflt
        self.cfg = {"interval": geti(self.interval_var, 1, 1440, DEFAULT_INTERVAL_MIN),
                    "dur": geti(self.dur_var, 1, 60, DEFAULT_DURATION_S),
                    "rtt": bool(self.rtt_var.get()), "down": bool(self.down_var.get()),
                    "up": bool(self.up_var.get())}
        self._render_status()

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    # ---- スケジューラ ----

    def start(self):
        if self.running:
            return
        c = self.cfg
        if not (c["rtt"] or c["down"] or c["up"]):
            self._set_msg("計測項目が全部OFFです", "bad")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._tick()

    def stop(self):
        self._stop.set()
        self._next_at = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self._tick_job:
            self.ctx.root.after_cancel(self._tick_job)
            self._tick_job = None
        self._render_status()

    def run_once(self):
        """スケジューラとは別に単発実行。二重に走らせないよう定期実行中は無視。"""
        if self.running or (self._thread and self._thread.is_alive()):
            self._set_msg("計測中です", "warn")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._one_shot, daemon=True)
        self._thread.start()
        self._set_msg("計測中…", "muted")

    def on_close(self):
        self._stop.set()
        if self._tick_job:
            try:
                self.ctx.root.after_cancel(self._tick_job)
            except tk.TclError:
                pass
            self._tick_job = None
        if self._thread:
            self._thread.join(timeout=3)  # 計測中なら残るが daemon なのでプロセス終了を妨げない

    def _one_shot(self):
        c = dict(self.cfg)
        rec = measure_once(c["rtt"], c["down"], c["up"], c["dur"])
        self._post(rec)

    def _loop(self):
        while not self._stop.is_set():
            c = dict(self.cfg)
            self._ui(lambda: self._set_msg("計測中…", "muted"))
            rec = measure_once(c["rtt"], c["down"], c["up"], c["dur"])
            self._post(rec)
            wait_s = max(60, self.cfg["interval"] * 60)
            self._next_at = time.time() + wait_s
            self._stop.wait(wait_s)

    def _post(self, rec):
        """計測結果を保存して UI へ反映。ワーカースレッドから呼ばれる。"""
        if rec is None:
            return
        try:
            append_record(self.path, rec)
        except OSError as e:
            self._ui(lambda: self._set_msg(f"保存に失敗: {e}", "bad"))
            return
        rec["_dt"] = datetime.fromisoformat(rec["ts"])
        errs = [v for k, v in rec.items() if k.endswith("_error")]

        def apply():
            self.records.append(rec)
            self.records.sort(key=lambda r: r["_dt"])
            if errs:
                self._set_msg(f"一部の計測に失敗: {errs[0]}", "warn")
            else:
                parts = [f"{METRICS[k][0]} {rec[k]}{METRICS[k][3]}" for k in METRICS if k in rec]
                self._set_msg("✓ " + " / ".join(parts) if parts else "✓ 計測完了", "good")
            self.refresh()
        self._ui(apply)

    def _ui(self, fn):
        try:
            self.ctx.root.after(0, fn)
        except (tk.TclError, RuntimeError):
            pass  # 終了処理と競合した場合

    def _tick(self):
        self._render_status()
        if self.running:
            self._tick_job = self.ctx.root.after(1000, self._tick)

    # ---- 表示 ----

    def _set_msg(self, text, kind="muted"):
        self._msg, self._msg_kind = text, kind
        self._render_status()

    def _render_status(self):
        if not hasattr(self, "status"):
            return
        c = self.cfg
        per, day = estimate_traffic(self.records, c["rtt"], c["down"], c["up"],
                                    c["dur"], c["interval"])
        bits = [f"履歴 {len(self.records)} 件"]
        if self.running:
            if self._next_at:
                left = max(0, int(self._next_at - time.time()))
                bits.append(f"次回 {datetime.fromtimestamp(self._next_at):%H:%M:%S} "
                            f"(あと {left // 60:d}分{left % 60:02d}秒)")
            else:
                bits.append("計測中…")
        else:
            bits.append("停止中")
        bits.append(f"推定通信量 1回 約{fmt_bytes(per)} / 1日 約{fmt_bytes(day)}")
        if self._msg:
            bits.append(self._msg)
        t = self.ctx.theme
        self.status.config(text="   |   ".join(bits),
                           foreground=t.get(self._msg_kind, t["muted"]) if self._msg else t["muted"])

    def refresh(self):
        self.draw()
        self._render_status()

    def export_csv(self):
        if not self.records:
            self._set_msg("エクスポートするデータがありません", "warn")
            return
        nd.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out = nd.RESULTS_DIR / f"trend_{datetime.now():%Y%m%d_%H%M%S}.csv"
        cols = ["ts", "dow", "hour", "down_mbps", "up_mbps", "rtt_ms", "rtt_max_ms", "loss_pct"]
        heads = ["日時", "曜日", "時", "下りMbps", "上りMbps", "RTTms", "RTT最大ms", "ロス%"]
        try:
            with open(out, "w", newline="", encoding="utf-8-sig") as f:  # Excel対策で BOM 付き
                w = csv.writer(f)
                w.writerow(heads)
                for r in self.records:
                    w.writerow([r.get("ts", ""), DOW_JA[int(r.get("dow", 0)) % 7]]
                               + [r.get(k, "") if r.get(k) is not None else "" for k in cols[2:]])
        except OSError as e:
            self._set_msg(f"CSV出力に失敗: {e}", "bad")
            return
        self._set_msg(f"✓ 出力: {out.name}", "good")

    # ---- 描画 ----

    def _size(self):
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        return (w if w > 10 else 900), (h if h > 10 else 380)  # 初回は 1 が返ることがある

    def _view_records(self):
        hours = dict((n, h) for n, h in PERIODS).get(self.period_var.get())
        return filter_period(self.records, hours)

    def draw(self):
        c = self.canvas
        c.delete("all")
        w, h = self._size()
        recs = self._view_records()
        if not recs:
            c.create_text(w / 2, h / 2, text="データがありません\n「今すぐ1回」または「定期実行を開始」で計測してください",
                          fill=self.ctx.theme["muted"], font=(self.ctx.font, 11), justify="center")
            self.summary.config(text="まだ計測データがありません。")
            return
        {"series": self._draw_series, "hourly": self._draw_hourly,
         "heatmap": self._draw_heatmap}[self.view_var.get()](recs, w, h)
        self._draw_summary(recs)

    def _frame(self, w, h, left=56, right=58, top=26, bottom=48):
        """プロット領域の矩形 (x0,y0,x1,y1)。狭すぎる場合でも潰れないよう最低幅を確保。"""
        x0, y0 = left, top
        x1, y1 = max(left + 60, w - right), max(top + 60, h - bottom)
        t = self.ctx.theme
        self.canvas.create_rectangle(x0, y0, x1, y1, outline=t["graph_grid"], width=1)
        return x0, y0, x1, y1

    def _ygrid(self, x0, y0, x1, y1, vmax, unit, side="left", color=None):
        """水平グリッド + 縦軸目盛。side='right' で右側に描く。"""
        t = self.ctx.theme
        color = color or t["muted"]
        for i in range(6):
            v = vmax * i / 5
            y = scale(v, 0, vmax, y1, y0)
            if 0 < i < 5:
                self.canvas.create_line(x0, y, x1, y, fill=t["graph_grid"])
            lab = f"{v:.0f}" if vmax >= 10 else f"{v:.1f}"
            self.canvas.create_text(x0 - 6 if side == "left" else x1 + 6, y, text=lab,
                                    anchor="e" if side == "left" else "w",
                                    fill=color, font=(self.ctx.font, 8))
        self.canvas.create_text(x0 - 6 if side == "left" else x1 + 6, y0 - 13, text=unit,
                                anchor="e" if side == "left" else "w", fill=color,
                                font=(self.ctx.font, 8))

    def _legend(self, x, y, items):
        t = self.ctx.theme
        for label, col in items:
            self.canvas.create_line(x, y, x + 16, y, fill=col, width=3)
            tid = self.canvas.create_text(x + 21, y, text=label, anchor="w", fill=t["fg"],
                                          font=(self.ctx.font, 8))
            x = self.canvas.bbox(tid)[2] + 14

    # --- ビュー1: 時系列 ---

    def _draw_series(self, recs, w, h):
        t = self.ctx.theme
        x0, y0, x1, y1 = self._frame(w, h)
        ts = [r["_dt"].timestamp() for r in recs]
        t0, t1 = min(ts), max(ts)
        if t1 - t0 < 60:
            t0, t1 = t0 - 300, t1 + 300
        spd = [v for k in ("down_mbps", "up_mbps") for _, v in _values(recs, k)]
        rtt = [v for _, v in _values(recs, "rtt_ms")]
        smax = nice_ceil(max(spd) if spd else 1)
        rmax = nice_ceil(max(rtt) if rtt else 1)
        self._ygrid(x0, y0, x1, y1, smax, "Mbps", "left")
        if rtt:
            self._ygrid(x0, y0, x1, y1, rmax, "ms", "right", t["bad"])

        span_h = (t1 - t0) / 3600
        fmt = ("%H:%M:%S" if span_h < 0.25 else "%H:%M") if span_h <= 36 else \
              ("%m/%d %H:%M" if span_h <= 24 * 10 else "%m/%d")
        for i in range(5):
            tv = t0 + (t1 - t0) * i / 4
            x = scale(tv, t0, t1, x0, x1)
            if 0 < i < 4:
                self.canvas.create_line(x, y0, x, y1, fill=t["graph_grid"])
            self.canvas.create_text(x, y1 + 8, text=datetime.fromtimestamp(tv).strftime(fmt),
                                    anchor="n", fill=t["muted"], font=(self.ctx.font, 8))

        for key, (name, ckey, _, unit) in METRICS.items():
            vmax = rmax if key == "rtt_ms" else smax
            pts = [(scale(r["_dt"].timestamp(), t0, t1, x0, x1), scale(v, 0, vmax, y1, y0))
                   for r, v in _values(recs, key)]
            if not pts:
                continue
            col = t[ckey]
            if len(pts) > 1:
                self.canvas.create_line(*[c for p in pts for c in p], fill=col, width=2)
            if len(pts) <= 200:  # 点が多いと潰れるだけなので間引く
                for px, py in pts:
                    self.canvas.create_oval(px - 2.5, py - 2.5, px + 2.5, py + 2.5,
                                            fill=col, outline=t["graph_bg"])
        self._legend(x0 + 8, y0 + 12, [(f"{n} ({u})", t[c]) for n, c, _, u in METRICS.values()])
        self.canvas.create_text(x1, y1 + 26, anchor="e", fill=t["muted"], font=(self.ctx.font, 8),
                                text=f"{len(recs)} 件  ({recs[0]['_dt']:%m/%d %H:%M} 〜 {recs[-1]['_dt']:%m/%d %H:%M})")

    # --- ビュー2: 時間帯別 (最重要) ---

    def _draw_hourly(self, recs, w, h):
        t = self.ctx.theme
        x0, y0, x1, y1 = self._frame(w, h, bottom=72)
        stats = {k: hourly_stats(recs, k) for k in METRICS}
        spd = [s["max"] for k in ("down_mbps", "up_mbps") for s in stats[k].values()]
        rtt = [s["max"] for s in stats["rtt_ms"].values()]
        smax = nice_ceil(max(spd) if spd else 1)
        rmax = nice_ceil(max(rtt) if rtt else 1)
        self._ygrid(x0, y0, x1, y1, smax, "Mbps", "left")
        if rtt:
            self._ygrid(x0, y0, x1, y1, rmax, "ms", "right", t["bad"])

        bw = (x1 - x0) / 24.0
        step = 1 if bw >= 26 else 2
        for hh in range(24):
            cx = x0 + (hh + 0.5) * bw
            if hh % step == 0:
                self.canvas.create_text(cx, y1 + 6, text=f"{hh}", anchor="n", fill=t["muted"],
                                        font=(self.ctx.font, 8))
            n = max((stats[k].get(hh, {}).get("n", 0) for k in METRICS), default=0)
            if n:
                self.canvas.create_text(cx, y1 + 21, text=f"{n}", anchor="n",
                                        fill=t["muted"] if n >= MIN_SAMPLES else t["warn"],
                                        font=(self.ctx.font, 7))
            if hh % 6 == 0 and hh:
                self.canvas.create_line(x0 + hh * bw, y0, x0 + hh * bw, y1, fill=t["graph_grid"])

        # 下り/上り: 各時間帯スロット内に min-max の帯 + 中央値の太い横棒
        barw = max(3.0, bw * 0.30)
        for key, off in (("down_mbps", -0.19), ("up_mbps", 0.19)):
            col = t[METRICS[key][1]]
            for hh, s in sorted(stats[key].items()):
                thin = s["n"] < MIN_SAMPLES          # サンプル不足は薄く描く
                fill = mix(col, t["graph_bg"], 0.72 if thin else 0.55)
                med_col = mix(col, t["graph_bg"], 0.55 if thin else 0.0)
                cx = x0 + (hh + 0.5) * bw + off * bw
                ytop = scale(s["max"], 0, smax, y1, y0)
                ybot = scale(s["min"], 0, smax, y1, y0)
                if ybot - ytop < 2:
                    ytop, ybot = (ytop + ybot) / 2 - 1, (ytop + ybot) / 2 + 1
                self.canvas.create_rectangle(cx - barw / 2, ytop, cx + barw / 2, ybot,
                                             fill=fill, outline="")
                ym = scale(s["med"], 0, smax, y1, y0)
                self.canvas.create_line(cx - barw / 2 - 1, ym, cx + barw / 2 + 1, ym,
                                        fill=med_col, width=2)

        # RTT: 右軸に中央値の折れ線 + min-max のひげ
        col = t["bad"]
        pts = []
        for hh, s in sorted(stats["rtt_ms"].items()):
            cx = x0 + (hh + 0.5) * bw
            thin = s["n"] < MIN_SAMPLES
            self.canvas.create_line(cx, scale(s["min"], 0, rmax, y1, y0),
                                    cx, scale(s["max"], 0, rmax, y1, y0),
                                    fill=mix(col, t["graph_bg"], 0.7 if thin else 0.45))
            pts.append((cx, scale(s["med"], 0, rmax, y1, y0), thin))
        if len(pts) > 1:
            self.canvas.create_line(*[c for p in pts for c in p[:2]], fill=col, width=2)
        for px, py, thin in pts:
            self.canvas.create_oval(px - 3, py - 3, px + 3, py + 3,
                                    fill=mix(col, t["graph_bg"], 0.6 if thin else 0.0),
                                    outline=t["graph_bg"])

        self._legend(x0 + 8, y0 + 12,
                     [("下り 中央値/最小〜最大", t["good"]), ("上り 中央値/最小〜最大", t["warn"]),
                      ("RTT 中央値/最小〜最大 (右軸)", t["bad"])])
        self.canvas.create_text(x1, y1 + 40, anchor="ne", fill=t["muted"], font=(self.ctx.font, 8),
                                text=f"横軸=時 / 下段の数字=その時間帯のサンプル数 "
                                     f"(橙={MIN_SAMPLES}件未満・帯も薄く表示)")

    # --- ビュー3: 曜日×時間帯ヒートマップ ---

    def _draw_heatmap(self, recs, w, h):
        t = self.ctx.theme
        key = self.metric_var.get() if self.metric_var.get() in METRICS else "down_mbps"
        name, ckey, higher_better, unit = METRICS[key]
        cells = dow_hour_stats(recs, key)
        x0, y0, x1, y1 = self._frame(w, h, left=44, right=20, top=26, bottom=64)
        cw, ch = (x1 - x0) / 24.0, (y1 - y0) / 7.0
        if not cells:
            self.canvas.create_text((x0 + x1) / 2, (y0 + y1) / 2, text=f"{name} のデータがありません",
                                    fill=t["muted"], font=(self.ctx.font, 10))
            return
        vals = [c["med"] for c in cells.values()]
        lo, hi = min(vals), max(vals)
        # 遅い=赤 / 速い=緑。RTT は大きい方が悪いので向きを反転する
        cols = [t["bad"], t["warn"], t["good"]] if higher_better else [t["good"], t["warn"], t["bad"]]

        for d in range(7):
            self.canvas.create_text(x0 - 8, y0 + (d + 0.5) * ch, text=DOW_JA[d], anchor="e",
                                    fill=t["fg"], font=(self.ctx.font, 9))
        step = 1 if cw >= 24 else 2
        for hh in range(0, 24, step):
            self.canvas.create_text(x0 + (hh + 0.5) * cw, y1 + 6, text=f"{hh}", anchor="n",
                                    fill=t["muted"], font=(self.ctx.font, 8))

        show_num = cw >= 38 and ch >= 20
        for d in range(7):
            for hh in range(24):
                cx0, cy0 = x0 + hh * cw, y0 + d * ch
                cx1, cy1 = cx0 + cw, cy0 + ch
                s = cells.get((d, hh))
                if not s:  # データ無しは無色 (背景のまま)
                    self.canvas.create_rectangle(cx0, cy0, cx1, cy1, fill=t["graph_bg"],
                                                 outline=mix(t["graph_bg"], t["graph_grid"], 0.5))
                    continue
                frac = (s["med"] - lo) / (hi - lo) if hi > lo else 0.5
                col = ramp(cols, frac)
                if s["n"] < MIN_SAMPLES:  # サンプル不足は背景寄りに薄める
                    col = mix(col, t["graph_bg"], 0.55)
                self.canvas.create_rectangle(cx0, cy0, cx1, cy1, fill=col, outline=t["graph_bg"])
                if show_num:
                    self.canvas.create_text((cx0 + cx1) / 2, (cy0 + cy1) / 2,
                                            text=f"{s['med']:.0f}",
                                            fill=readable_on(col, "#101010", "#f0f0f0"),
                                            font=(self.ctx.font, 8))

        # カラースケールの凡例
        lx, ly, lw2, lh2 = x0, y1 + 28, min(200, (x1 - x0) * 0.4), 10
        for i in range(int(lw2)):
            self.canvas.create_line(lx + i, ly, lx + i, ly + lh2, fill=ramp(cols, i / max(lw2 - 1, 1)))
        self.canvas.create_rectangle(lx, ly, lx + lw2, ly + lh2, outline=t["graph_grid"])
        self.canvas.create_text(lx, ly + lh2 + 3, text=f"{lo:.0f}", anchor="nw", fill=t["muted"],
                                font=(self.ctx.font, 8))
        self.canvas.create_text(lx + lw2, ly + lh2 + 3, text=f"{hi:.0f} {unit}", anchor="ne",
                                fill=t["muted"], font=(self.ctx.font, 8))
        self.canvas.create_text(lx + lw2 + 14, ly + lh2 / 2, anchor="w", fill=t["muted"],
                                font=(self.ctx.font, 8),
                                text=f"{name}の中央値 / セル内数値={unit} / "
                                     f"薄いセル={MIN_SAMPLES}件未満 / 無色=データ無し")

    # --- サマリ ---

    def _draw_summary(self, recs):
        t = self.ctx.theme
        lines = []
        for key, (name, _, higher, unit) in METRICS.items():
            hs = hourly_stats(recs, key)
            if not hs:
                continue
            s = summarize(hs, higher)
            if not s["ok"]:
                lines.append(f"{name}: データ不足 "
                             f"({MIN_SAMPLES}件以上ある時間帯 {s['enough']}/{s['hours']}、"
                             f"計 {s['samples']} 件) — 傾向はまだ判断できません")
                continue
            ratio = f" / {s['ratio']:.2f}倍" if s["ratio"] else ""
            w_lab, b_lab = ("最も遅い", "最も速い") if higher else ("最も悪い", "最も良い")
            lines.append(f"{name}: {w_lab} {s['worst_h']:02d}時台 {s['worst']:.1f}{unit}  ／  "
                         f"{b_lab} {s['best_h']:02d}時台 {s['best']:.1f}{unit}  ／  "
                         f"差 {s['diff']:.1f}{unit}{ratio}")
        loss = [v for _, v in _values(recs, "loss_pct") if v > 0]
        if loss:
            lines.append(f"パケットロスが出た計測: {len(loss)} 件 (最大 {max(loss):.0f}%)")
        self.summary.config(text="\n".join(lines) or "集計できる値がありません。",
                            bg=t["card_bg"], fg=t["fg"])


# ---------- 自己テスト ----------

def _selftest():
    import tempfile
    from pathlib import Path

    # --- 座標変換 ---
    assert scale(5, 0, 10, 100, 200) == 150
    assert scale(0, 0, 10, 400, 100) == 400 and scale(10, 0, 10, 400, 100) == 100
    assert scale(5, 5, 5, 0, 100) == 50, "値域ゼロは中央"
    assert scale(-5, 0, 10, 0, 100) == -50, "範囲外も線形に外挿する"
    assert nice_ceil(0) == 1.0 and nice_ceil(-3) == 1.0
    assert nice_ceil(292) == 300.0, nice_ceil(292)
    assert nice_ceil(7.2) == 8.0 and nice_ceil(1000) == 1000.0 and nice_ceil(1001) == 1500.0
    assert mix("#000000", "#ffffff", 0.5) == "#808080"
    assert ramp(["#000000", "#ffffff"], 0.0) == "#000000"
    assert ramp(["#000000", "#808080", "#ffffff"], 1.0) == "#ffffff"
    assert ramp(["#ff0000"], 0.3) == "#ff0000"
    assert readable_on("#ffffff", "d", "l") == "d" and readable_on("#000000", "d", "l") == "l"
    assert fmt_bytes(1.7e8) == "170.0MB" and fmt_bytes(8.2e9) == "8.2GB"

    # --- 合成データ: 夜(20〜23時)だけ遅い / 週末の夜はさらに遅い ---
    base = datetime(2026, 8, 10, 0, 0)
    recs = []
    for day in range(7):
        for hh in range(24):
            for k in range(4):
                dt = base + timedelta(days=day, hours=hh, minutes=k * 15)
                night = 20 <= hh <= 23
                down = (60.0 if dt.weekday() >= 5 else 100.0) if night else 280.0
                rtt = 45.0 if night else 7.0
                recs.append({"ts": dt.isoformat(timespec="seconds"), "dow": dt.weekday(),
                             "hour": dt.hour, "down_mbps": down + k, "up_mbps": down * 0.6,
                             "rtt_ms": rtt + k * 0.5, "loss_pct": 0, "_dt": dt})

    hs = hourly_stats(recs, "down_mbps")
    assert len(hs) == 24 and all(s["n"] == 28 for s in hs.values()), [s["n"] for s in hs.values()]
    assert hs[3]["med"] == 281.5 and hs[3]["min"] == 280.0 and hs[3]["max"] == 283.0, hs[3]
    # 20時台は平日100系/週末60系が混ざる -> 中央値は平日側 (5/7が平日)
    assert 60 < hs[21]["med"] < 105, hs[21]
    assert hs[21]["min"] == 60.0 and hs[21]["max"] == 103.0, hs[21]

    s = summarize(hs, higher_is_better=True)
    assert s["ok"] and 20 <= s["worst_h"] <= 23, s
    assert not (20 <= s["best_h"] <= 23), s
    assert s["ratio"] > 2.0 and s["diff"] > 150, s
    srtt = summarize(hourly_stats(recs, "rtt_ms"), higher_is_better=False)
    assert srtt["ok"] and 20 <= srtt["worst_h"] <= 23, srtt   # RTT は大きい方が悪い
    assert srtt["best"] < srtt["worst"], srtt

    # --- サンプル不足の判定 ---
    few = [r for r in recs if r["hour"] == 5][:2]
    assert summarize(hourly_stats(few, "down_mbps"), True)["ok"] is False
    two = hourly_stats([r for r in recs if r["hour"] in (5, 6)][:8], "down_mbps")
    assert set(two) == {5, 6} and summarize(two, True, min_n=3)["ok"] is True, two
    assert summarize(two, True, min_n=99)["ok"] is False
    assert summarize({}, True)["ok"] is False and summarize({}, True)["enough"] == 0
    assert hourly_stats([{"hour": 1, "dow": 0, "down_mbps": None}], "down_mbps") == {}
    assert hourly_stats([{"hour": 1, "dow": 0, "down_mbps": True}], "down_mbps") == {}, "boolは数値扱いしない"

    # --- 曜日×時間帯 ---
    dh = dow_hour_stats(recs, "down_mbps")
    assert len(dh) == 7 * 24 and dh[(0, 3)]["n"] == 4
    assert dh[(5, 21)]["med"] == 61.5 and dh[(0, 21)]["med"] == 101.5, (dh[(5, 21)], dh[(0, 21)])
    assert dh[(6, 10)]["med"] == 281.5
    assert dow_hour_stats([], "down_mbps") == {}

    # --- 期間フィルタ ---
    now = datetime(2026, 8, 17, 0, 0)
    assert len(filter_period(recs, None, now)) == len(recs)
    assert len(filter_period(recs, 24, now)) == 24 * 4      # 最終日ぶん
    assert len(filter_period(recs, 24 * 7, now)) == len(recs)
    assert filter_period(recs, 1, datetime(2030, 1, 1)) == []   # 期間外は全部落ちる
    assert filter_period([], 24, now) == []

    # --- JSONL 読み書き (壊れた行を含む) ---
    tmp = Path(tempfile.mkdtemp()) / "sub" / "t.jsonl"
    for r in recs[:3]:
        append_record(tmp, r)
    with open(tmp, "a", encoding="utf-8") as f:
        f.write("これはJSONではない\n")
        f.write("\n")
        f.write('{"ts": "2026-08-10T00:45:00", "down_mbps": 1.5}\n')   # 正常 (dow/hour 補完)
        f.write('{"down_mbps": 9}\n')                                   # ts 無し
        f.write('{"ts": "not-a-date", "down_mbps": 9}\n')               # 時刻が壊れている
        f.write('[1,2,3]\n')                                            # dict ではない
        f.write('{"ts": "2026-08-10T00:15:00", "down_mbps": 2.5}\n')    # 順序が前後している
    got = load_records(tmp)
    assert len(got) == 5, [g["ts"] for g in got]
    assert [g["ts"] for g in got] == sorted(g["ts"] for g in got), "時刻昇順に並べ直される"
    last = got[-1]
    assert last["hour"] == 0 and last["down_mbps"] == 1.5, last
    assert last["dow"] == base.weekday(), last  # dow 欠落時は ts から補完される
    assert "_dt" not in json.loads(tmp.read_text(encoding="utf-8").splitlines()[0]), "内部キーは保存しない"
    assert load_records(tmp.parent / "no-such-file.jsonl") == []

    # --- 通信量の見積り ---
    per, day = estimate_traffic([], True, True, True, 3, 30)
    assert 1.5e8 < per < 1.9e8, per            # 実測 1回約170MB と整合
    assert abs(day - per * 48) < 1, (per, day)
    per_rtt, _ = estimate_traffic([], True, False, False, 3, 30)
    assert per_rtt < 5000, per_rtt             # RTT だけならほぼ無通信
    assert estimate_traffic([], False, False, False, 3, 30)[0] == 0
    withdata = [{"down_bytes": 1e8, "duration_s": 3}] * 3
    per2, _ = estimate_traffic(withdata, False, True, False, 3, 30)
    assert abs(per2 - 1e8) < 1, per2           # 実測 bytes があればそちらを使う

    # --- 計測: 全項目OFFなら何もしない ---
    assert measure_once(False, False, False, 3) is None

    print("trend selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import tkinter as tk
    from tkinter import ttk
    import sv_ttk
    root = tk.Tk(); root.geometry("1200x720"); sv_ttk.set_theme("dark")
    root.title("定期実行 + 時間帯トレンド")
    class Ctx: pass
    ctx = Ctx(); ctx.root = root; ctx.font = "Segoe UI"
    ctx.theme = {"bg":"#1c1c1c","card_bg":"#2b2b2b","fg":"#f2f2f2","muted":"#9d9d9d",
                 "good":"#3fb950","warn":"#e3b341","bad":"#f85149",
                 "graph_bg":"#232323","graph_grid":"#3a3a3a"}
    frame = ttk.Frame(root); frame.pack(fill="both", expand=True)
    tab = TrendTab(frame, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
