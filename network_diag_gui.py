#!/usr/bin/env python3
"""network_diag.pyのGUI版。ping/パケロスのリアルタイム監視、通信量ランキング(プロセス別)、
フル診断(Wi-Fi/IPv6/経路/DNS/スループット/バッファブロート/ISP情報)、前後比較をタブで切り替えて使う。
見た目はsv_ttk(Windows 11風のFluentテーマ)でダッシュボード風に。"""
import csv
import json
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import sv_ttk

import network_diag as nd
import traffic_monitor as tm
from settings_store import settings
from settings_window import SettingsWindow

TARGET_COLORS = {"ゲートウェイ": "#2e86de", "1.1.1.1": "#f2994a", "8.8.8.8": "#9b59b6"}

THEMES = {
    "dark": {
        "bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
        "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
        "graph_bg": "#232323", "graph_grid": "#3a3a3a",
    },
    "light": {
        "bg": "#fafafa", "card_bg": "#ffffff", "fg": "#1a1a1a", "muted": "#666666",
        "good": "#1a7f37", "warn": "#9a6700", "bad": "#cf222e",
        "graph_bg": "#ffffff", "graph_grid": "#e2e2e2",
    },
}

FONT = "Segoe UI"


def format_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


class PingMonitor:
    def __init__(self, host):
        self.host = host
        self.sent = 0
        self.received = 0
        self.current_ms = None
        self.min_ms = None
        self.max_ms = None
        self.rtts = []
        self.history = []  # (datetime, rtt_or_None) 全件、CSVエクスポート/グラフ描画用
        self.consecutive_losses = 0
        self._stop = threading.Event()
        self._thread = None

    def start(self, interval_s):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(interval_s,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self, interval_s):
        while not self._stop.is_set():
            t0 = time.perf_counter()
            result = nd.measure_latency(self.host, count=1, timeout_ms=1000)
            self.sent += 1
            ms = result.get("avg_ms")
            self.history.append((datetime.now(), ms))
            if ms is not None:
                self.received += 1
                self.current_ms = ms
                self.rtts.append(ms)
                self.min_ms = ms if self.min_ms is None else min(self.min_ms, ms)
                self.max_ms = ms if self.max_ms is None else max(self.max_ms, ms)
                self.consecutive_losses = 0
            else:
                self.current_ms = None
                self.consecutive_losses += 1
            elapsed = time.perf_counter() - t0
            self._stop.wait(max(0, interval_s - elapsed))

    @property
    def loss_pct(self):
        return round((self.sent - self.received) / self.sent * 100, 1) if self.sent else 0.0

    @property
    def avg_ms(self):
        return round(sum(self.rtts) / len(self.rtts), 1) if self.rtts else None

    def reset(self):
        self.sent = self.received = 0
        self.rtts = []
        self.history = []
        self.consecutive_losses = 0
        self.current_ms = self.min_ms = self.max_ms = None


class App:
    TARGET_ROWS = ["ゲートウェイ", "1.1.1.1", "8.8.8.8"]

    def __init__(self, root):
        self.root = root
        self.font = FONT  # 各機能タブへ ctx として self を渡すため
        self.theme_name = settings.get("general.theme")
        sv_ttk.set_theme(self.theme_name)
        root.title("ネットワーク診断")
        # 経路監視タブが12列、タブ自体も多いため既定幅は広めに取る
        root.geometry(f"{settings.get('general.window_width')}x{settings.get('general.window_height')}")
        root.minsize(1000, 620)

        header = ttk.Frame(root, padding=(16, 12))
        header.pack(fill="x")
        ttk.Label(header, text="ネットワーク診断", font=(FONT, 15, "bold")).pack(side="left")
        self.theme_btn = ttk.Button(header, text="☀ ライト", width=10, command=self.toggle_theme)
        self.theme_btn.pack(side="right")
        ttk.Button(header, text="⚙ 設定", width=8, command=self.open_settings).pack(side="right", padx=(0, 8))

        # 画面が16枚あり ttk.Notebook のタブ行では見出しが見切れるため、左の一覧で切り替える。
        body = ttk.Frame(root)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.nav = tk.Listbox(body, width=16, activestyle="none", exportselection=False,
                              bd=0, highlightthickness=0, font=(FONT, 10))
        self.nav.pack(side="left", fill="y", padx=(0, 12))
        self.pane = ttk.Frame(body)
        self.pane.pack(side="left", fill="both", expand=True)

        self.pages = []        # [(ラベル, Frame)] 表示順
        self.plugin_tabs = []

        # ダッシュボードは他ページの結果を集約して「今どうか」を出すので先頭に置く。
        self._load_plugin("dashboard_tab", "DashboardTab", "ダッシュボード")

        self.ping_tab = self._add_page("Ping")
        self.traffic_tab = self._add_page("通信量")
        self.full_tab = self._add_page("フル診断")
        self.compare_tab = self._add_page("前後比較")

        self._build_ping_tab()
        self._build_traffic_tab()
        self._build_full_tab()
        self._build_compare_tab()

        # 各機能タブは独立モジュール。契約は __init__(parent, ctx) / on_theme_changed() / on_close()。
        # 1本が壊れても他が道連れにならないよう個別に組み込む。
        for module_name, class_name, label in (
            ("watchdog_tab", "WatchdogTab", "常時監視"),
            ("pathmon_tab", "PathMonTab", "経路監視"),
            ("lanscan_tab", "LanScanTab", "LAN機器"),
            ("topology_tab", "TopologyTab", "構成図"),
            ("dnsaudit_tab", "DnsAuditTab", "DNS監査"),
            ("portcheck_tab", "PortCheckTab", "ポート"),
            ("ipv6_tab", "IPv6Tab", "IPv6監査"),
            ("geomap_tab", "GeoMapTab", "経路地図"),
            ("atlas_tab", "AtlasTab", "外部から測定"),
            ("bandwidth_tab", "BandwidthTab", "帯域/VPN"),
            ("services_tab", "ServicesTab", "サービス"),
            ("trend_tab", "TrendTab", "トレンド"),
            ("tuning_tab", "TuningTab", "Windows設定"),
            ("report_tab", "ReportTab", "レポート"),
            # 他タブの保存結果を読む立場なので最後に置く
            ("advisor_tab", "AdvisorTab", "総合診断"),
        ):
            self._load_plugin(module_name, class_name, label)

        self.nav.bind("<<ListboxSelect>>", self._on_nav_select)
        self.nav.selection_set(0)
        self._show_page(0)
        self.apply_theme_to_raw_widgets()

    # ---- ページ切り替え ----

    def _load_plugin(self, module_name, class_name, label):
        """機能タブを1本読み込む。失敗しても他のページを巻き添えにしない。

        ページは1本につき必ず1枚。以前は _add_page のあとにコンストラクタが落ちると
        空ページとエラーページの2枚が残っていた(一覧に同じ名前が並ぶ)。
        先にインスタンスを作り、成功したページだけを一覧へ載せる。
        """
        frame = ttk.Frame(self.pane)
        try:
            instance = getattr(__import__(module_name), class_name)(frame, self)
        except Exception as e:
            for child in frame.winfo_children():   # 途中まで組まれた部品を捨てる
                child.destroy()
            ttk.Label(frame, text=f"{module_name} の読み込みに失敗しました:\n{e}",
                      padding=20, justify="left").pack(anchor="w")
            label += " (エラー)"
        else:
            self.plugin_tabs.append(instance)
        self.nav.insert("end", f"  {label}")
        self.pages.append((label, frame))

    def _add_page(self, label):
        frame = ttk.Frame(self.pane)
        self.nav.insert("end", f"  {label}")
        self.pages.append((label, frame))
        return frame

    def _on_nav_select(self, _event=None):
        sel = self.nav.curselection()
        if sel:
            self._show_page(sel[0])

    def _show_page(self, index):
        for _, frame in self.pages:
            frame.pack_forget()
        self.pages[index][1].pack(fill="both", expand=True)

    @property
    def page_labels(self):
        return [label for label, _ in self.pages]

    @property
    def theme(self):
        return THEMES[self.theme_name]

    def toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        sv_ttk.set_theme(self.theme_name)
        self.theme_btn.config(text="🌙 ダーク" if self.theme_name == "light" else "☀ ライト")
        self.apply_theme_to_raw_widgets()
        self._notify_plugins("on_theme_changed")

    def apply_theme_to_raw_widgets(self):
        t = self.theme
        if hasattr(self, "nav"):
            self.nav.configure(bg=t["card_bg"], fg=t["fg"],
                               selectbackground="#0a84ff", selectforeground="#ffffff")
        for name, card in getattr(self, "cards", {}).items():
            card["card"].config(bg=t["card_bg"])
            card["inner"].config(bg=t["card_bg"])
            card["name_label"].config(bg=t["card_bg"], fg=t["muted"])
            card["sub_label"].config(bg=t["card_bg"], fg=t["muted"])
            card["value_label"].config(bg=t["card_bg"])
        for lbl in getattr(self, "legend_labels", []):
            lbl.config(bg=t["bg"])
        if hasattr(self, "graph_canvas"):
            self.graph_canvas.config(bg=t["graph_bg"], highlightbackground=t["graph_grid"])
            self._draw_graph()
        if hasattr(self, "full_summary"):
            self.full_summary.config(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"])

    def _health_color(self, ms, loss_pct):
        t = self.theme
        if ms is None or loss_pct >= 5:
            return t["bad"]
        if ms >= settings.get("ping.warn_ms") or loss_pct > 0:
            return t["warn"]
        return t["good"]

    # ---------- Ping / パケロス ----------

    def _build_ping_tab(self):
        self.monitors = {name: PingMonitor(None) for name in self.TARGET_ROWS}
        self.cards = {}
        self._running = False
        self._poll_job = None

        cards_frame = ttk.Frame(self.ping_tab, padding=(4, 12, 4, 4))
        cards_frame.pack(fill="x")
        for i, name in enumerate(self.TARGET_ROWS):
            cards_frame.columnconfigure(i, weight=1)
            card = tk.Frame(cards_frame, bd=0, highlightthickness=0)
            card.grid(row=0, column=i, padx=6, sticky="nsew")
            tk.Frame(card, bg=TARGET_COLORS[name], height=4).pack(fill="x")
            inner = tk.Frame(card, padx=16, pady=10)
            inner.pack(fill="both", expand=True)
            name_label = tk.Label(inner, text=name, font=(FONT, 10, "bold"), anchor="w")
            name_label.pack(fill="x")
            value_label = tk.Label(inner, text="- ms", font=(FONT, 26, "bold"), anchor="w")
            value_label.pack(fill="x")
            sub_label = tk.Label(inner, text="平均 - / 最大 - / 損失 -%  (送受信 -/-)", font=(FONT, 9), anchor="w")
            sub_label.pack(fill="x")
            self.cards[name] = {"card": card, "inner": inner, "name_label": name_label,
                                 "value_label": value_label, "sub_label": sub_label}

        controls = ttk.Frame(self.ping_tab, padding=(4, 8))
        controls.pack(fill="x")
        ttk.Label(controls, text="更新間隔(秒)").grid(row=0, column=0, padx=(0, 6))
        self.interval_var = tk.DoubleVar(value=settings.get("ping.interval_s"))
        ttk.Spinbox(controls, from_=0.2, to=5.0, increment=0.2, textvariable=self.interval_var, width=6).grid(row=0, column=1)
        self.start_btn = ttk.Button(controls, text="▶  計測開始", style="Accent.TButton", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=2, padx=8)
        self.stop_btn = ttk.Button(controls, text="⏸  停止", command=self.stop_monitoring, state="disabled")
        self.stop_btn.grid(row=0, column=3, padx=4)
        ttk.Button(controls, text="↺  リセット", command=self.reset_monitoring).grid(row=0, column=4, padx=4)
        ttk.Button(controls, text="⬇  CSVへエクスポート", command=self.export_ping_csv).grid(row=0, column=5, padx=4)
        self.alert_label = ttk.Label(controls, text="", font=(FONT, 9, "bold"))
        self.alert_label.grid(row=0, column=6, padx=12, sticky="w")

        legend_frame = ttk.Frame(self.ping_tab, padding=(4, 0))
        legend_frame.pack(fill="x")
        self.legend_labels = []
        for name, color in TARGET_COLORS.items():
            lbl = tk.Label(legend_frame, text=f"● {name}", fg=color, font=(FONT, 9))
            lbl.pack(side="left", padx=(0, 14))
            self.legend_labels.append(lbl)

        self.graph_canvas = tk.Canvas(self.ping_tab, height=180, highlightthickness=1)
        self.graph_canvas.pack(fill="both", expand=True, padx=4, pady=(6, 4))

    def start_monitoring(self):
        if self._running:
            return
        gateway = nd.get_default_gateway() or "192.168.1.1"
        hosts = {"ゲートウェイ": gateway, "1.1.1.1": "1.1.1.1", "8.8.8.8": "8.8.8.8"}
        for name, host in hosts.items():
            self.monitors[name].host = host
            self.monitors[name].start(self.interval_var.get())
        self._running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._poll()

    def stop_monitoring(self):
        for m in self.monitors.values():
            m.stop()
        self._running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self._poll_job:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None

    def reset_monitoring(self):
        for m in self.monitors.values():
            m.reset()

    def _poll(self):
        alerts = []
        t = self.theme
        for name, m in self.monitors.items():
            card = self.cards[name]
            color = self._health_color(m.current_ms, m.loss_pct)
            card["value_label"].config(
                text=f"{m.current_ms}ms" if m.current_ms is not None else "timeout",
                fg=color,
            )
            card["sub_label"].config(
                text=f"平均 {m.avg_ms if m.avg_ms is not None else '-'} / "
                     f"最大 {m.max_ms if m.max_ms is not None else '-'} / "
                     f"損失 {m.loss_pct}%  (送受信 {m.received}/{m.sent})",
                fg=t["bad"] if m.loss_pct > 0 else t["muted"],
            )
            if m.consecutive_losses >= settings.get("ping.loss_alert_streak"):
                alerts.append(name)
        self.alert_label.config(
            text=f"⚠ 応答なし継続中: {', '.join(alerts)}" if alerts else "",
            foreground=t["bad"],
        )
        if alerts:
            self.root.bell()
        self._draw_graph()
        if self._running:
            self._poll_job = self.root.after(300, self._poll)

    def _draw_graph(self):
        c = self.graph_canvas
        t = self.theme
        c.delete("all")
        w = c.winfo_width() or 900
        h = c.winfo_height() or 180
        window = settings.get("ping.graph_points")
        all_vals = [v for m in self.monitors.values() for v in m.rtts[-window:] if v is not None]
        max_ms = max(all_vals) * 1.15 if all_vals else 50
        for frac in (0.25, 0.5, 0.75):
            y = h - frac * (h - 10) - 5
            c.create_line(0, y, w, y, fill=t["graph_grid"])
        for name, m in self.monitors.items():
            recent = m.history[-window:]
            if len(recent) < 2:
                continue
            color = TARGET_COLORS.get(name, t["fg"])
            step = w / max(len(recent) - 1, 1)
            points = []
            for i, (_, ms) in enumerate(recent):
                x = i * step
                y = h - (min(ms, max_ms) / max_ms * (h - 10)) - 5 if ms is not None else h - 5
                points.append((x, y, ms is not None))
            for (x0, y0, ok0), (x1, y1, ok1) in zip(points, points[1:]):
                if ok0 and ok1:
                    c.create_line(x0, y0, x1, y1, fill=color, width=2, smooth=True)
                elif not ok1:
                    c.create_oval(x1 - 3, h - 8, x1 + 3, h - 2, fill=t["bad"], outline="")

    def export_ping_csv(self):
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"ping_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["対象", "時刻", "RTT(ms)"])
            for name, m in self.monitors.items():
                for ts, ms in m.history:
                    writer.writerow([name, ts.isoformat(timespec="seconds"), ms if ms is not None else "timeout"])
        self.alert_label.config(text=f"✓ CSV出力: {path.name}", foreground=self.theme["good"])

    # ---------- 通信量ランキング ----------

    def _build_traffic_tab(self):
        self.traffic_monitor = tm.TrafficMonitor()
        self._traffic_running = False
        self._traffic_poll_job = None

        note = (
            "このPC自身のIPv4通信のみが対象です(管理者権限が必要)。同じLAN上の他の家庭内機器の通信は\n"
            "スイッチ構成上、原理的にこのPCからは見えません。IPv6の通信もこの版では対象外です。"
        )
        ttk.Label(self.traffic_tab, text=note, foreground="#888", padding=(4, 12, 4, 0)).pack(fill="x")

        top = ttk.Frame(self.traffic_tab, padding=(4, 10))
        top.pack(fill="x")
        self.traffic_start_btn = ttk.Button(top, text="⏺  キャプチャ開始", style="Accent.TButton", command=self.start_traffic)
        self.traffic_start_btn.grid(row=0, column=0, padx=(0, 6))
        self.traffic_stop_btn = ttk.Button(top, text="⏸  停止", command=self.stop_traffic, state="disabled")
        self.traffic_stop_btn.grid(row=0, column=1, padx=4)
        self.pcap_var = tk.BooleanVar(value=settings.get("capture.save_pcap"))
        ttk.Checkbutton(top, text="pcapファイルにも保存 (Wiresharkで開ける)",
                        variable=self.pcap_var).grid(row=0, column=2, padx=(12, 0))
        self.traffic_status = ttk.Label(top, text="")
        self.traffic_status.grid(row=0, column=3, padx=12, sticky="w")

        columns = ("process", "hostname", "ip", "port", "proto", "dir", "bytes", "packets")
        headers = ["プロセス", "ホスト名", "相手IP", "ポート", "プロトコル", "方向", "通信量", "パケット数"]
        self.traffic_tree = ttk.Treeview(self.traffic_tab, columns=columns, show="headings", height=16)
        for col, head in zip(columns, headers):
            self.traffic_tree.heading(col, text=head)
            self.traffic_tree.column(col, width=90, anchor="w")
        self.traffic_tree.pack(fill="both", expand=True, padx=4, pady=(0, 8))

    def start_traffic(self):
        if self._traffic_running:
            return
        pcap_path = None
        if self.pcap_var.get():
            nd.RESULTS_DIR.mkdir(exist_ok=True)
            pcap_path = nd.RESULTS_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.traffic_monitor.start(pcap_path=pcap_path)
        self._traffic_running = True
        self.traffic_start_btn.config(state="disabled")
        self.traffic_stop_btn.config(state="normal")
        self._poll_traffic()

    def stop_traffic(self):
        self.traffic_monitor.stop()
        self._traffic_running = False
        self.traffic_start_btn.config(state="normal")
        self.traffic_stop_btn.config(state="disabled")
        if self._traffic_poll_job:
            self.root.after_cancel(self._traffic_poll_job)
            self._traffic_poll_job = None

    def _poll_traffic(self):
        if self.traffic_monitor.error:
            self.traffic_status.config(text=self.traffic_monitor.error, foreground=self.theme["bad"])
            self.stop_traffic()
            return
        status = f"ローカルIP: {self.traffic_monitor.local_ip or '取得中...'}"
        if self.traffic_monitor.pcap_path:
            status += f"   pcap: {self.traffic_monitor.pcap_path.name} ({self.traffic_monitor.pcap_packets}パケット)"
        self.traffic_status.config(text=status, foreground=self.theme["muted"])

        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)
        for row in self.traffic_monitor.top_talkers(limit=30):
            hostname = row["hostname"]
            if not hostname:
                self.traffic_monitor.resolve_hostname_async(row["remote_ip"])
                hostname = ""
            self.traffic_tree.insert("", "end", values=(
                row.get("process") or "-",
                hostname,
                row["remote_ip"],
                row.get("remote_port") or "-",
                row["proto"],
                row["direction"],
                format_bytes(row["bytes"]),
                row["packets"],
            ))
        if self._traffic_running:
            self._traffic_poll_job = self.root.after(1000, self._poll_traffic)

    # ---------- フル診断 ----------

    def _build_full_tab(self):
        full = ttk.Frame(self.full_tab, padding=(4, 12))
        full.pack(fill="x")
        ttk.Label(full, text="ラベル").grid(row=0, column=0, padx=(0, 6))
        self.label_var = tk.StringVar(value="test")
        ttk.Entry(full, textvariable=self.label_var, width=20).grid(row=0, column=1, padx=(0, 8))
        self.full_btn = ttk.Button(full, text="⚡  実行 (1〜2分)", style="Accent.TButton", command=self.run_full_diag)
        self.full_btn.grid(row=0, column=2)
        self.full_status = ttk.Label(full, text="", foreground="#888")
        self.full_status.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))

        self.full_summary = tk.Text(self.full_tab, height=18, wrap="word", state="disabled",
                                     relief="flat", padx=12, pady=10, font=("Consolas", 10))
        self.full_summary.pack(fill="both", expand=True, padx=4, pady=(4, 8))

    def run_full_diag(self):
        self.full_btn.config(state="disabled")
        label = self.label_var.get().strip() or "test"

        def progress(msg):
            self.root.after(0, lambda: self.full_status.config(text=msg))

        def worker():
            try:
                result = nd.run_diagnostics(label, progress=progress)
                path = nd.save_result(result)
                progress(f"完了: {path}")
                self.root.after(0, lambda: self._show_full_summary(result))
                self.root.after(0, self.refresh_compare_files)
                self.root.after(0, lambda: self._notify_plugins("refresh_files"))
            except Exception as e:
                progress(f"エラー: {e}")
            finally:
                self.root.after(0, lambda: self.full_btn.config(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def _show_full_summary(self, result):
        def g(section, *keys, default="-"):
            d = result.get(section) or {}
            for k in keys:
                if not isinstance(d, dict):
                    return default
                d = d.get(k)
            return default if d is None else d

        grade = result.get("grade") or {}
        lines = []
        if grade.get("grade"):
            lines += [
                f"総合グレード: {grade['grade']}  ({grade.get('score')}点 / 100)",
                f"  {grade.get('comment', '')}",
            ]
            for b in grade.get("breakdown", []):
                pts = f"{b['点']}/{b['満点']}" if b["点"] is not None else "測定不可"
                lines.append(f"    {b['項目']}: {b['実測']}  → {pts}")
            lines.append("")
        lines += [
            f"公開IP: {g('public_ip_info', 'ip')} / ISP: {g('public_ip_info', 'org')} ({g('public_ip_info', 'city')})",
            f"IPv6: グローバルアドレス={g('ipv6', 'has_global_address')} 到達確認={g('ipv6', 'egress_reachable')}",
            f"経路MTU: {g('path_mtu', 'mtu')}  → {g('path_mtu', 'interpretation')}",
            f"NATタイプ: {g('nat', 'nat_type')}",
            "",
            f"下り: 単一 {g('throughput', 'single', 'mbps')} Mbps / 6並列 {g('throughput', 'parallel6', 'mbps')} Mbps",
            f"上り: 単一 {g('upload', 'single', 'mbps')} Mbps / 6並列 {g('upload', 'parallel6', 'mbps')} Mbps",
            f"IPv4 {g('ip_version_compare', 'ipv4', 'mbps')} Mbps "
            f"(握手{g('ip_version_compare', 'ipv4', 'tcp_handshake_ms')}ms) vs "
            f"IPv6 {g('ip_version_compare', 'ipv6', 'mbps')} Mbps "
            f"(握手{g('ip_version_compare', 'ipv6', 'tcp_handshake_ms')}ms)",
            f"ジッター: {g('jitter', 'jitter_ms')}ms / MOS {g('jitter', 'mos')} ({g('jitter', 'quality')})",
            f"時刻ズレ: {g('time_sync', 'offset_ms')}ms "
            f"({g('time_sync', 'direction')} / {g('time_sync', 'verdict')})",
            f"QUIC(HTTP3): {g('quic', 'verdict')}",
            f"DNSBL: {g('dnsbl', 'verdict')}",
            f"TCP再送率: {g('link_stats', 'tcp_retransmit_pct')}%  "
            f"(送信 {g('link_stats', 'tcp_segments_sent')} / 再送 {g('link_stats', 'tcp_segments_retransmitted')})",
            f"バッファブロート: アイドル{g('bufferbloat', 'idle_latency', 'avg_ms')}ms → "
            f"負荷時{g('bufferbloat', 'loaded_latency', 'avg_ms')}ms "
            f"(損失{g('bufferbloat', 'loaded_latency', 'loss_pct')}%) / 簡易RPM近似値{g('bufferbloat', 'rpm_approx')}",
            "",
            "traceroute:",
        ]
        for target, hops in result.get("traceroute", {}).items():
            lines.append(f"  → {target}")
            if isinstance(hops, list):
                for hop in hops:
                    info = hop.get("ip_info") or {}
                    org = f" [{info.get('org')}]" if info.get("org") else ""
                    lines.append(f"    hop{hop['hop']}: {hop.get('ip') or 'timeout'} {hop.get('avg_ms', '-')}ms{org}")

        self.full_summary.config(state="normal")
        self.full_summary.delete("1.0", "end")
        self.full_summary.insert("1.0", "\n".join(lines))
        self.full_summary.config(state="disabled")

    # ---------- 前後比較 ----------

    def _build_compare_tab(self):
        self.compare_files = []

        top = ttk.Frame(self.compare_tab, padding=(4, 12))
        top.pack(fill="x")
        ttk.Button(top, text="↻  一覧を更新", command=self.refresh_compare_files).grid(row=0, column=0, padx=(0, 10))
        ttk.Label(top, text="A").grid(row=0, column=1, padx=(0, 4))
        self.compare_a_var = tk.StringVar()
        self.compare_a_combo = ttk.Combobox(top, textvariable=self.compare_a_var, width=38, state="readonly")
        self.compare_a_combo.grid(row=0, column=2, padx=(0, 10))
        ttk.Label(top, text="B").grid(row=0, column=3, padx=(0, 4))
        self.compare_b_var = tk.StringVar()
        self.compare_b_combo = ttk.Combobox(top, textvariable=self.compare_b_var, width=38, state="readonly")
        self.compare_b_combo.grid(row=0, column=4, padx=(0, 10))
        ttk.Button(top, text="🔍  比較する", style="Accent.TButton", command=self.run_compare).grid(row=0, column=5)

        columns = ("metric", "a", "b")
        self.compare_tree = ttk.Treeview(self.compare_tab, columns=columns, show="headings", height=18)
        for col, head in zip(columns, ["指標", "A", "B"]):
            self.compare_tree.heading(col, text=head)
            self.compare_tree.column(col, width=240, anchor="w")
        self.compare_tree.pack(fill="both", expand=True, padx=4, pady=(4, 8))

        self.refresh_compare_files()

    def refresh_compare_files(self):
        self.compare_files = nd.list_result_files()
        display = [f"{p.stem}" for p in self.compare_files]
        self.compare_a_combo["values"] = display
        self.compare_b_combo["values"] = display
        if display:
            if not self.compare_a_var.get():
                self.compare_a_var.set(display[0])
            if not self.compare_b_var.get() and len(display) > 1:
                self.compare_b_var.set(display[1])

    def run_compare(self):
        idx_a = self.compare_a_combo.current()
        idx_b = self.compare_b_combo.current()
        if idx_a < 0 or idx_b < 0:
            return
        result_a = json.loads(self.compare_files[idx_a].read_text(encoding="utf-8"))
        result_b = json.loads(self.compare_files[idx_b].read_text(encoding="utf-8"))
        metrics_a = nd.flatten_metrics(result_a)
        metrics_b = nd.flatten_metrics(result_b)

        for item in self.compare_tree.get_children():
            self.compare_tree.delete(item)
        for key in metrics_a:
            self.compare_tree.insert("", "end", values=(key, metrics_a.get(key, "-"), metrics_b.get(key, "-")))

    def open_settings(self):
        SettingsWindow.open(self.root, self.theme, on_applied=self.on_settings_applied)

    def on_settings_applied(self):
        """設定ウィンドウで「適用」されたときに呼ばれる。即座に効くものだけ反映する。"""
        theme = settings.get("general.theme")
        if theme != self.theme_name:
            self.theme_name = theme
            sv_ttk.set_theme(theme)
            self.theme_btn.config(text="🌙 ダーク" if theme == "light" else "☀ ライト")
            self.apply_theme_to_raw_widgets()
        self.interval_var.set(settings.get("ping.interval_s"))
        self.pcap_var.set(settings.get("capture.save_pcap"))
        self._notify_plugins("on_settings_changed")
        self._draw_graph()

    def _notify_plugins(self, method_name):
        """機能タブへの通知。1本が例外を投げても他のタブと終了処理を巻き込まない。"""
        for tab in getattr(self, "plugin_tabs", []):
            try:
                getattr(tab, method_name, lambda: None)()
            except Exception:
                pass

    def on_close(self):
        self.stop_monitoring()
        self.stop_traffic()
        self._notify_plugins("on_close")
        self.root.destroy()


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
