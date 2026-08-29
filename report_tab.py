#!/usr/bin/env python3
"""診断結果JSON(results/*.json)から、オフラインで開ける単一HTMLレポートと
Obsidian貼り付け用Markdownを生成するタブモジュール。

グラフは外部ライブラリを使わず手書きのインラインSVGで描画する。CSSはインライン、
ダーク/ライトは prefers-color-scheme + CSS変数で両対応。

GUI本体からは:
    import report_tab
    tab = report_tab.ReportTab(notebook_frame, ctx)
で組み込む。単体でも `python report_tab.py` で起動確認できる。
自己テストは `python report_tab.py --selftest`。
"""
import html as _html
import json
import math
import re
import shutil
import threading
import tkinter as tk
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import ttk

import network_diag as nd

OBSIDIAN_DIR = Path.home() / "Documents" / "NetworkDiagReports"
CONTRACT_MBPS = 1000.0  # 契約速度(1Gbps)。達成率と棒グラフの基準線に使う

DNS_LABELS = {"router": "ルーター(GW)"}


# ---------- 値の取り出し (欠損に強い) ----------

def g(d, *keys, default=None):
    """ネストしたdictから安全に取り出す。途中がdictでない/Noneなら default。"""
    return nd._get_nested(d, *keys, default=default)


def num(v):
    """数値なら数値、それ以外(None/"-"/dict/bool)は None。"""
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def fmt(v, unit="", digits=1):
    n = num(v)
    if n is None:
        return "-"
    if isinstance(n, int):
        s = str(n)
    else:
        s = f"{n:.{digits}f}"
        if "." in s:  # "250" を rstrip("0") で壊さないよう小数点がある時だけ末尾0を落とす
            s = s.rstrip("0").rstrip(".")
    return f"{s}{unit}"


def esc(v):
    return _html.escape("-" if v is None else str(v))


def fmt_ts(ts):
    return str(ts).replace("T", " ") if ts else "-"


def label_of(result):
    return str(result.get("label") or "unnamed")


# results/ には他機能(LANスキャン等)のJSONも混ざるので、診断結果らしいものだけを対象にする
DIAG_KEYS = ("latency", "throughput", "bufferbloat", "dns", "traceroute")


def is_diag_result(data):
    return isinstance(data, dict) and "timestamp" in data and any(k in data for k in DIAG_KEYS)


# ---------- SVG 棒グラフ ----------

def nice_max(v):
    """目盛りがキリの良い値になるよう上限を丸める(34.7 -> 40)。"""
    if not v or v <= 0:
        return 1.0
    exp = math.floor(math.log10(v))
    base = 10.0 ** exp
    for m in (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if v <= m * base + 1e-9:
            return m * base
    return 10 * base


def svg_bars(rows, floor_max=None, unit="", ref=None, ref_label="",
             width=760, bar_h=24, gap=16, label_w=190):
    """横棒グラフ。rows = [{"label":str, "note":str, "value":float|None, "color":"var(--accent)"}]

    floor_max: 目盛り上限の下限値(契約速度など)。ref: 破線の基準線。
    値が None の行は「測定失敗」と表示してバーを描かない。
    """
    vals = [v for v in (num(r.get("value")) for r in rows) if v is not None]
    hi = nice_max(max([max(vals) * 1.08 if vals else 0.0, float(floor_max or 0), float(ref or 0), 1.0]))
    plot_w = width - label_w - 104
    top = 18
    height = top + len(rows) * (bar_h + gap) + 26
    axis_y = height - 22

    p = [f'<svg class="chart" viewBox="0 0 {width} {height}" preserveAspectRatio="xMinYMid meet" role="img">']

    # 目盛り線
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        x = label_w + plot_w * frac
        p.append(f'<line class="grid" x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{axis_y - 4}" />')
        anchor = "start" if frac == 0 else ("end" if frac == 1.0 else "middle")
        p.append(f'<text class="axis" x="{x:.1f}" y="{axis_y + 10}" text-anchor="{anchor}">'
                 f'{esc(fmt(hi * frac, unit, 0 if hi >= 100 else 1))}</text>')

    for i, r in enumerate(rows):
        y = top + i * (bar_h + gap)
        cy = y + bar_h / 2
        v = num(r.get("value"))
        color = r.get("color") or "var(--accent)"
        p.append(f'<text class="blabel" x="{label_w - 12}" y="{cy - (6 if r.get("note") else 0):.1f}" '
                 f'text-anchor="end" dominant-baseline="central">{esc(r.get("label"))}</text>')
        if r.get("note"):
            p.append(f'<text class="bnote" x="{label_w - 12}" y="{cy + 9:.1f}" text-anchor="end" '
                     f'dominant-baseline="central">{esc(r["note"])}</text>')
        p.append(f'<rect class="track" x="{label_w}" y="{y}" width="{plot_w:.1f}" height="{bar_h}" rx="5" />')
        if v is None:
            p.append(f'<text class="bfail" x="{label_w + 10}" y="{cy:.1f}" dominant-baseline="central">測定失敗</text>')
            continue
        bw = max(3.0, min(v / hi, 1.0) * plot_w)
        p.append(f'<rect x="{label_w}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="5" fill="{color}" />')
        p.append(f'<text class="bvalue" x="{label_w + bw + 9:.1f}" y="{cy:.1f}" dominant-baseline="central">'
                 f'{esc(fmt(v, unit, 2))}</text>')

    if ref:
        x = label_w + min(float(ref) / hi, 1.0) * plot_w
        p.append(f'<line class="refline" x1="{x:.1f}" y1="{top - 10}" x2="{x:.1f}" y2="{axis_y - 4}" />')
        p.append(f'<text class="reftext" x="{x - 5:.1f}" y="{top - 12}" text-anchor="end">{esc(ref_label)}</text>')

    p.append("</svg>")
    return "\n".join(p)


# ---------- 各セクション ----------

def _rate_color(pct):
    if pct is None:
        return "var(--muted)"
    return "var(--good)" if pct >= 60 else ("var(--warn)" if pct >= 25 else "var(--bad)")


def throughput_chart(result):
    # 上り(upload)は後から追加された項目。無い結果ファイルでは行ごと出さない。
    groups = [("throughput", "下り", "var(--accent)", "var(--accent2)")]
    if isinstance(result.get("upload"), dict):
        groups.append(("upload", "上り", "var(--good)", "var(--warn)"))
    rows = []
    for section, prefix, c1, c2 in groups:
        data = result.get(section) or {}
        for key, name, color in (("single", "単一接続", c1), ("parallel6", "6並列", c2)):
            mbps = num(g(data, key, "mbps"))
            err = g(data, key, "error")
            note = (f"契約比 {mbps / CONTRACT_MBPS * 100:.1f}%" if mbps is not None
                    else (f"エラー: {str(err)[:36]}" if err else "データなし"))
            rows.append({"label": f"{prefix} {name}", "note": note, "value": mbps, "color": color})
    return svg_bars(rows, floor_max=CONTRACT_MBPS, unit=" Mbps",
                    ref=CONTRACT_MBPS, ref_label="契約 1Gbps")


def metrics_table(result):
    """nd.flatten_metrics の主要指標をそのまま表にする。上流に項目が増えても自動で載る。"""
    rows = "".join(f"<tr><td>{esc(k)}</td><td><strong>{esc(fmt_ts(v) if '日時' in k else v)}</strong></td></tr>"
                   for k, v in nd.flatten_metrics(result).items())
    return f'<table><thead><tr><th>指標</th><th>値</th></tr></thead><tbody>{rows}</tbody></table>'


def latency_chart(result):
    lat = result.get("latency") or {}
    names = [("gateway", "ゲートウェイ"), ("1.1.1.1", "1.1.1.1"), ("8.8.8.8", "8.8.8.8")]
    rows = []
    for key, name in names:
        if key not in lat:
            continue
        loss = num(g(lat, key, "loss_pct"))
        rows.append({"label": f"{name} 平均", "note": f"損失 {fmt(loss, '%', 0)}" if loss is not None else "",
                     "value": num(g(lat, key, "avg_ms")), "color": "var(--accent)"})
        rows.append({"label": f"{name} 最大", "note": "", "value": num(g(lat, key, "max_ms")),
                     "color": "var(--accent-dim)"})
    if not rows:
        return '<p class="empty">遅延データがありません。</p>'
    return svg_bars(rows, unit=" ms")


def bufferbloat_chart(result):
    bb = result.get("bufferbloat") or {}
    idle = num(g(bb, "idle_latency", "avg_ms"))
    loaded = num(g(bb, "loaded_latency", "avg_ms"))
    pct = num(bb.get("increase_pct"))
    rows = [
        {"label": "アイドル時 RTT", "note": f"最大 {fmt(g(bb, 'idle_latency', 'max_ms'), 'ms', 0)}",
         "value": idle, "color": "var(--good)"},
        {"label": "負荷時 RTT", "note": f"最大 {fmt(g(bb, 'loaded_latency', 'max_ms'), 'ms', 0)} / "
                                       f"損失 {fmt(g(bb, 'loaded_latency', 'loss_pct'), '%', 0)}",
         "value": loaded, "color": "var(--bad)" if (pct or 0) >= 150 else "var(--warn)"},
    ]
    chart = svg_bars(rows, unit=" ms")
    grade, gcolor = bufferbloat_grade(pct)
    badge = (f'<div class="bb-badge"><span class="pill" style="background:{gcolor}">{esc(grade)}</span>'
             f'<div><strong>悪化率 {fmt(pct, "%")}</strong>'
             f'<span class="muted">（+{fmt(bb.get("increase_ms"), "ms", 0)} / 簡易RPM近似値 '
             f'{fmt(bb.get("rpm_approx"), "", 0)}）</span></div></div>')
    return badge + chart


def bufferbloat_grade(pct):
    if pct is None:
        return "不明", "var(--muted)"
    if pct < 30:
        return "良好", "var(--good)"
    if pct < 100:
        return "許容", "var(--warn)"
    return "要改善", "var(--bad)"


def summary_cards(result):
    pub = result.get("public_ip_info") or {}
    ipv6 = result.get("ipv6") or {}
    thr = result.get("throughput") or {}
    bb = result.get("bufferbloat") or {}
    up = result.get("upload") or {}
    single = num(g(thr, "single", "mbps"))
    parallel = num(g(thr, "parallel6", "mbps"))
    pct = num(bb.get("increase_pct"))
    v6_ok = bool(ipv6.get("has_global_address")) and bool(ipv6.get("egress_reachable"))

    def rate_card(title, mbps, grade=True):
        rate = mbps / CONTRACT_MBPS * 100 if mbps is not None else None
        # 上りは契約1Gbps(下り基準)と比べても仕方ないので色付けしない
        return (title, esc(fmt(mbps, " Mbps", 2)), f"契約比 {fmt(rate, '%') if rate is not None else '-'}",
                _rate_color(rate) if grade else "var(--fg)")

    cards = [
        ("公開IP / ISP", esc(pub.get("ip") or "-"),
         esc(f"{pub.get('org') or 'ISP不明'} / {pub.get('city') or '-'}"), "var(--fg)"),
        ("IPv6", "利用可" if v6_ok else "不可",
         f"グローバルaddr {len(ipv6.get('global_addresses') or [])}件 / "
         f"既定経路 {'有' if ipv6.get('has_default_route') else '無'} / "
         f"疎通 {'OK' if ipv6.get('egress_reachable') else 'NG'}",
         "var(--good)" if v6_ok else "var(--bad)"),
        rate_card("下り(単一)", single),
        rate_card("下り(6並列)", parallel),
    ]
    if up:
        cards.append(rate_card("上り(6並列)", num(g(up, "parallel6", "mbps")), grade=False))
    cards += [
        ("バッファブロート", esc(fmt(pct, "%")),
         f"{fmt(g(bb, 'idle_latency', 'avg_ms'), 'ms', 0)} → {fmt(g(bb, 'loaded_latency', 'avg_ms'), 'ms', 0)}"
         f" / {bufferbloat_grade(pct)[0]}", bufferbloat_grade(pct)[1]),
    ]
    out = ['<div class="cards">']
    for title, value, sub, color in cards:
        out.append(f'<div class="card"><div class="card-title">{esc(title)}</div>'
                   f'<div class="card-value" style="color:{color}">{value}</div>'
                   f'<div class="card-sub">{esc(sub)}</div></div>')
    out.append("</div>")
    return "\n".join(out)


def traceroute_tables(result):
    tr = result.get("traceroute") or {}
    if not isinstance(tr, dict) or not tr:
        return '<p class="empty">tracerouteデータがありません。</p>'
    out = []
    for target, hops in tr.items():
        out.append(f'<h4>→ {esc(target)}</h4>')
        if not isinstance(hops, list) or not hops:
            err = g(tr, target, "error") if isinstance(hops, dict) else None
            out.append(f'<p class="empty">{esc(err or "ホップ情報なし")}</p>')
            continue
        rows = []
        for hop in hops:
            if not isinstance(hop, dict):
                continue
            info = hop.get("ip_info") or {}
            org = info.get("org") or ("(情報なし)" if hop.get("ip") else "-")
            loc = " ".join(x for x in (info.get("city"), info.get("country")) if x)
            ip = hop.get("ip") or "* * *"
            ms = "timeout" if hop.get("timeout") else fmt(hop.get("avg_ms"), " ms")
            cls = ' class="dim"' if hop.get("timeout") else ""
            loc_html = f'<span class="muted"> / {esc(loc)}</span>' if loc else ""
            rows.append(f'<tr{cls}><td>{esc(hop.get("hop"))}</td><td class="mono">{esc(ip)}</td>'
                        f'<td>{esc(ms)}</td><td>{esc(org)}{loc_html}</td></tr>')
        out.append('<table><thead><tr><th>ホップ</th><th>IP</th><th>応答時間</th><th>組織</th></tr></thead>'
                   f'<tbody>{"".join(rows)}</tbody></table>')
    return "\n".join(out)


def dns_table(result):
    dns = result.get("dns") or {}
    if not isinstance(dns, dict) or not dns:
        return '<p class="empty">DNSデータがありません。</p>'
    best = min((num(g(dns, k, "avg_ms")) for k in dns if num(g(dns, k, "avg_ms")) is not None), default=None)
    rows = []
    for server, d in dns.items():
        avg = num(g(dns, server, "avg_ms"))
        ok, total = g(dns, server, "trials_ok", default=0), g(dns, server, "trials_total", default=0)
        mark = ' <span class="pill mini" style="background:var(--good)">最速</span>' if avg is not None and avg == best else ""
        rows.append(f'<tr><td class="mono">{esc(DNS_LABELS.get(server, server))}{mark}</td>'
                    f'<td><strong>{esc(fmt(avg, " ms"))}</strong></td><td>{esc(fmt(g(dns, server, "min_ms"), " ms"))}</td>'
                    f'<td>{esc(fmt(g(dns, server, "max_ms"), " ms"))}</td><td>{esc(ok)}/{esc(total)}</td></tr>')
    return ('<table><thead><tr><th>DNSサーバ</th><th>平均</th><th>最小</th><th>最大</th><th>成功</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


# ---------- before/after 差分 ----------

def direction(key):
    """指標名から「増えると良い(+1) / 減ると良い(-1) / 判定しない(0)」を推定する。
    nd.flatten_metrics の項目は今後も増減するため、キー名の完全一致表ではなく単位・語で判定する。"""
    k = str(key)
    if any(t in k for t in ("Mbps", "MOS", "RPM")):
        return 1
    if any(t in k for t in ("ms", "損失", "再送", "ジッター", "%")):
        return -1
    return 0


def diff_rows(a, b):
    """[(指標, A値, B値, 変化テキスト, 判定, css)] を返す。数値でない項目は変化なし扱い。"""
    ma, mb = nd.flatten_metrics(a), nd.flatten_metrics(b)
    rows = []
    for key in ma:
        va, vb = ma.get(key, "-"), mb.get(key, "-")
        if "日時" in key:
            va, vb = fmt_ts(va), fmt_ts(vb)
        na, nb = num(va), num(vb)
        dirn = direction(key)
        higher = None if dirn == 0 else (dirn > 0)
        if na is None or nb is None or higher is None:
            verdict, css, delta = ("変化なし", "same", "-") if str(va) == str(vb) else ("差異あり", "info", "→")
            rows.append((key, va, vb, delta, verdict, css))
            continue
        d = nb - na
        pct = (d / na * 100) if na else None
        delta = f"{'+' if d > 0 else ''}{fmt(d, '', 2)}" + (f" ({'+' if pct > 0 else ''}{pct:.1f}%)" if pct is not None else "")
        if abs(d) < 1e-9:
            verdict, css = "変化なし", "same"
        elif (d > 0) == higher:
            verdict, css = "改善", "good"
        else:
            verdict, css = "悪化", "bad"
        rows.append((key, va, vb, delta, verdict, css))
    return rows


def diff_table_html(a, b):
    rows = "".join(
        f'<tr class="{css}"><td>{esc(k)}</td><td>{esc(va)}</td><td>{esc(vb)}</td>'
        f'<td class="mono">{esc(delta)}</td><td><span class="verdict {css}">{esc(verdict)}</span></td></tr>'
        for k, va, vb, delta, verdict, css in diff_rows(a, b))
    return ('<table class="diff"><thead><tr><th>指標</th>'
            f'<th>A: {esc(label_of(a))}</th><th>B: {esc(label_of(b))}</th><th>変化</th><th>判定</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')


# ---------- HTML 全体 ----------

CSS = """
:root{
  --bg:#f5f6f8; --panel:#ffffff; --fg:#14181d; --muted:#5d6875; --border:#e2e6ec; --track:#eceff4;
  --accent:#2f6fed; --accent-dim:#9dbafa; --accent2:#8b5cf6;
  --good:#1a7f37; --warn:#b7791f; --bad:#cf222e;
  --good-bg:#e7f5ec; --bad-bg:#fdeced; --info-bg:#eef3fd;
  --shadow:0 1px 2px rgba(16,24,40,.05), 0 10px 28px rgba(16,24,40,.07);
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#16181c; --panel:#212429; --fg:#eef1f5; --muted:#98a2b0; --border:#31363e; --track:#2b2f36;
    --accent:#5b90ff; --accent-dim:#39518a; --accent2:#a684ff;
    --good:#3fb950; --warn:#e3b341; --bad:#f85149;
    --good-bg:#12291a; --bad-bg:#2c1416; --info-bg:#151f33;
    --shadow:0 1px 2px rgba(0,0,0,.4), 0 10px 28px rgba(0,0,0,.35);
  }
}
*{box-sizing:border-box}
body{margin:0;padding:32px 20px 64px;background:var(--bg);color:var(--fg);
  font-family:"Segoe UI","Yu Gothic UI","Meiryo","Hiragino Kaku Gothic ProN",system-ui,sans-serif;
  font-size:15px;line-height:1.65;-webkit-font-smoothing:antialiased}
.wrap{max-width:980px;margin:0 auto}
header.top{margin-bottom:28px;border-bottom:1px solid var(--border);padding-bottom:20px}
header.top h1{margin:0 0 6px;font-size:26px;letter-spacing:.01em}
.sub{color:var(--muted);font-size:13.5px}
.chips{margin-top:12px;display:flex;flex-wrap:wrap;gap:8px}
.chip{background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:12.5px;
  box-shadow:var(--shadow)}
section{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px 22px;
  margin-bottom:20px;box-shadow:var(--shadow)}
section h2{margin:0 0 4px;font-size:17px}
section h3{margin:26px 0 10px;font-size:15.5px;color:var(--fg)}
section h4{margin:18px 0 6px;font-size:13.5px;color:var(--muted);font-weight:600}
.hint{margin:0 0 16px;color:var(--muted);font-size:12.5px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0 4px}
.card{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.card-title{font-size:11.5px;color:var(--muted);letter-spacing:.04em}
.card-value{font-size:22px;font-weight:700;line-height:1.25;margin:2px 0;word-break:break-all}
.card-sub{font-size:11.5px;color:var(--muted)}
.chart{width:100%;height:auto;display:block;margin:8px 0 4px;overflow:visible}
.chart .grid{stroke:var(--border);stroke-width:1}
.chart .track{fill:var(--track)}
.chart .axis{fill:var(--muted);font-size:11px}
.chart .blabel{fill:var(--fg);font-size:12.5px}
.chart .bnote{fill:var(--muted);font-size:10.5px}
.chart .bvalue{fill:var(--fg);font-size:12.5px;font-weight:700}
.chart .bfail{fill:var(--bad);font-size:12px;font-weight:600}
.chart .refline{stroke:var(--warn);stroke-width:1.5;stroke-dasharray:5 4}
.chart .reftext{fill:var(--warn);font-size:11px;font-weight:600}
.chart text{font-family:inherit}
table{width:100%;border-collapse:collapse;margin:6px 0 10px;font-size:13.5px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;letter-spacing:.03em;
  border-bottom:1px solid var(--border);padding:7px 10px;white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tr.dim td{color:var(--muted)}
.mono{font-family:Consolas,"SF Mono",Menlo,monospace;font-size:12.5px}
.muted{color:var(--muted);font-weight:400}
.empty{color:var(--muted);font-size:13px;margin:6px 0}
.pill{display:inline-block;color:#fff;border-radius:999px;padding:2px 12px;font-size:12.5px;font-weight:700}
.pill.mini{padding:1px 8px;font-size:10.5px}
.bb-badge{display:flex;align-items:center;gap:12px;margin:10px 0 4px}
.verdict{font-weight:700;font-size:12.5px}
.verdict.good{color:var(--good)} .verdict.bad{color:var(--bad)}
.verdict.same,.verdict.info{color:var(--muted)}
table.diff tr.good{background:var(--good-bg)} table.diff tr.bad{background:var(--bad-bg)}
table.diff tr.info{background:var(--info-bg)}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:28px;line-height:1.8}
"""


def detail_section(result, title_prefix=""):
    return f"""
<section>
  <h2>{esc(title_prefix)}サマリ — {esc(label_of(result))}</h2>
  <p class="hint">計測日時 {esc(fmt_ts(result.get("timestamp")))}／ゲートウェイ {esc(result.get("gateway_ip") or "-")}</p>
  {summary_cards(result)}
  <h3>スループット（契約 1Gbps に対する到達度）</h3>
  {throughput_chart(result)}
  <h3>主要指標</h3>
  {metrics_table(result)}
  <h3>遅延（平均 / 最大）</h3>
  {latency_chart(result)}
  <h3>バッファブロート（アイドル時 vs 負荷時 RTT）</h3>
  {bufferbloat_chart(result)}
  <h3>経路（traceroute）</h3>
  {traceroute_tables(result)}
  <h3>DNS 応答時間</h3>
  {dns_table(result)}
</section>"""


def build_html(results):
    """results: [result] または [before, after]。単一HTML文字列を返す。"""
    results = [r for r in results if isinstance(r, dict)]
    if not results:
        raise ValueError("レポート対象の結果がありません")
    a = results[0]
    b = results[1] if len(results) > 1 else None
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"ネットワーク診断レポート {label_of(a)}" + (f" → {label_of(b)}" if b else "")

    chips = [f'計測 {fmt_ts(a.get("timestamp"))}']
    if b:
        chips.append(f'比較 {fmt_ts(b.get("timestamp"))}')
    chips.append(f"生成 {generated}")

    parts = [f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <h1>{esc(title)}</h1>
  <div class="sub">自宅ネット回線 実測診断レポート（オフライン閲覧可・外部リソース不使用）</div>
  <div class="chips">{"".join(f'<span class="chip">{esc(c)}</span>' for c in chips)}</div>
</header>"""]

    if b:
        parts.append(f"""
<section>
  <h2>前後比較（A: {esc(label_of(a))} → B: {esc(label_of(b))}）</h2>
  <p class="hint">緑=改善 / 赤=悪化。数値指標のみ変化量と変化率を算出しています。</p>
  {diff_table_html(a, b)}
</section>""")
        parts.append(detail_section(a, "A｜"))
        parts.append(detail_section(b, "B｜"))
    else:
        parts.append(detail_section(a))

    rpm_note = g(a, "bufferbloat", "rpm_note", default="")
    parts.append(f"""
<footer>
  {esc(rpm_note)}<br>
  network_diag / report_tab で生成。グラフはインラインSVG、外部CDN・スクリプトは使用していません。
</footer>
</div>
</body>
</html>""")
    return "\n".join(parts)


# ---------- Markdown (Obsidian用) ----------

def mdbar(v, hi, width=18):
    n = num(v)
    if n is None or not hi:
        return ""
    filled = int(round(max(0.0, min(n / hi, 1.0)) * width))
    return "`" + "█" * filled + "░" * (width - filled) + "`"


def _md_detail(result, heading):
    thr = result.get("throughput") or {}
    lat = result.get("latency") or {}
    bb = result.get("bufferbloat") or {}
    pub = result.get("public_ip_info") or {}
    ipv6 = result.get("ipv6") or {}
    single, parallel = num(g(thr, "single", "mbps")), num(g(thr, "parallel6", "mbps"))
    out = [f"## {heading}", "",
           f"- 計測日時: {fmt_ts(result.get('timestamp'))}",
           f"- 公開IP / ISP: `{pub.get('ip') or '-'}` / {pub.get('org') or '-'} ({pub.get('city') or '-'})",
           f"- IPv6: グローバルaddr {len(ipv6.get('global_addresses') or [])}件 / "
           f"既定経路 {'有' if ipv6.get('has_default_route') else '無'} / "
           f"疎通 {'OK' if ipv6.get('egress_reachable') else 'NG'}",
           "", "### スループット（契約1Gbps比）", "",
           "| 種別 | 実測 | 契約比 | |", "|---|---|---|---|"]
    sections = [("throughput", "下り")] + ([("upload", "上り")] if isinstance(result.get("upload"), dict) else [])
    for section, prefix in sections:
        data = result.get(section) or {}
        for key, name in (("single", "単一接続"), ("parallel6", "6並列")):
            v = num(g(data, key, "mbps"))
            rate = f"{v / CONTRACT_MBPS * 100:.1f}%" if v is not None else "-"
            err = g(data, key, "error")
            val = fmt(v, " Mbps", 2) if v is not None else f"測定失敗（{str(err)[:40] or 'データなし'}）"
            out.append(f"| {prefix} {name} | {val} | {rate} | {mdbar(v, CONTRACT_MBPS)} |")

    out += ["", "### 主要指標", "", "| 指標 | 値 |", "|---|---|"]
    out += [f"| {k} | {fmt_ts(v) if '日時' in k else v} |" for k, v in nd.flatten_metrics(result).items()]

    out += ["", "### 遅延", "", "| 対象 | 平均 | 最小 | 最大 | 損失 |", "|---|---|---|---|---|"]
    for key in ("gateway", "1.1.1.1", "8.8.8.8"):
        if key not in lat:
            continue
        name = "ゲートウェイ" if key == "gateway" else key
        out.append(f"| {name} | {fmt(g(lat, key, 'avg_ms'), ' ms')} | {fmt(g(lat, key, 'min_ms'), ' ms')} | "
                   f"{fmt(g(lat, key, 'max_ms'), ' ms')} | {fmt(g(lat, key, 'loss_pct'), '%', 0)} |")

    grade = bufferbloat_grade(num(bb.get("increase_pct")))[0]
    out += ["", "### バッファブロート", "",
            f"- アイドル時 {fmt(g(bb, 'idle_latency', 'avg_ms'), 'ms', 0)} → "
            f"負荷時 {fmt(g(bb, 'loaded_latency', 'avg_ms'), 'ms', 0)} "
            f"（+{fmt(bb.get('increase_ms'), 'ms', 0)} / **{fmt(bb.get('increase_pct'), '%')}** / 判定: {grade}）",
            f"- 負荷時の損失: {fmt(g(bb, 'loaded_latency', 'loss_pct'), '%', 0)} / "
            f"簡易RPM近似値: {fmt(bb.get('rpm_approx'), '', 0)}"]

    out += ["", "### 経路（traceroute）", ""]
    tr = result.get("traceroute") or {}
    for target, hops in tr.items() if isinstance(tr, dict) else []:
        out += [f"**→ {target}**", "", "| ホップ | IP | 応答 | 組織 |", "|---|---|---|---|"]
        if isinstance(hops, list):
            for hop in hops:
                if not isinstance(hop, dict):
                    continue
                info = hop.get("ip_info") or {}
                ms = "timeout" if hop.get("timeout") else fmt(hop.get("avg_ms"), " ms")
                out.append(f"| {hop.get('hop', '-')} | `{hop.get('ip') or '* * *'}` | {ms} | "
                           f"{info.get('org') or '-'} |")
        out.append("")

    out += ["### DNS 応答時間", "", "| サーバ | 平均 | 最小 | 最大 | 成功 |", "|---|---|---|---|---|"]
    dns = result.get("dns") or {}
    for server in dns if isinstance(dns, dict) else []:
        out.append(f"| {DNS_LABELS.get(server, server)} | {fmt(g(dns, server, 'avg_ms'), ' ms')} | "
                   f"{fmt(g(dns, server, 'min_ms'), ' ms')} | {fmt(g(dns, server, 'max_ms'), ' ms')} | "
                   f"{g(dns, server, 'trials_ok', default=0)}/{g(dns, server, 'trials_total', default=0)} |")
    out.append("")
    return "\n".join(out)


def build_markdown(results, html_name=""):
    results = [r for r in results if isinstance(r, dict)]
    if not results:
        raise ValueError("レポート対象の結果がありません")
    a = results[0]
    b = results[1] if len(results) > 1 else None
    title = f"ネットワーク診断 {label_of(a)}" + (f" → {label_of(b)}" if b else "")
    out = ["---",
           f"title: {title}",
           f"created: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
           f"measured: {fmt_ts(a.get('timestamp'))}",
           "tags:", "  - ネットワーク診断", "---", "",
           f"# {title}", ""]
    if html_name:
        out += [f"> グラフ付きHTML版: `{html_name}`", ""]

    if b:
        out += ["## 前後比較", "",
                f"| 指標 | A: {label_of(a)} | B: {label_of(b)} | 変化 | 判定 |", "|---|---|---|---|---|"]
        marks = {"good": "🟢 改善", "bad": "🔴 悪化", "same": "⚪ 変化なし", "info": "🔵 差異あり"}
        for k, va, vb, delta, verdict, css in diff_rows(a, b):
            out.append(f"| {k} | {va} | {vb} | {delta} | {marks.get(css, verdict)} |")
        out.append("")
        out.append(_md_detail(a, f"A: {label_of(a)}"))
        out.append(_md_detail(b, f"B: {label_of(b)}"))
    else:
        out.append(_md_detail(a, f"詳細: {label_of(a)}"))

    note = g(a, "bufferbloat", "rpm_note", default="")
    if note:
        out += ["---", "", f"> [!note] 注記", f"> {note}", ""]
    return "\n".join(out)


# ---------- ファイル出力 ----------

def safe_label(text):
    return re.sub(r'[\\/:*?"<>|\s]+', "_", str(text)).strip("_") or "report"


def write_report(paths, copy_to_obsidian=False):
    """paths: 結果JSONのPathを1つか2つ(古い順)。生成した (html_path, md_path, obsidian_path|None) を返す。"""
    results = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    label = "_vs_".join(safe_label(label_of(r)) for r in results)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nd.RESULTS_DIR.mkdir(exist_ok=True)
    html_path = nd.RESULTS_DIR / f"report_{label}_{stamp}.html"
    md_path = nd.RESULTS_DIR / f"report_{label}_{stamp}.md"
    html_path.write_text(build_html(results), encoding="utf-8")
    md_path.write_text(build_markdown(results, html_path.name), encoding="utf-8")

    obsidian_path = None
    if copy_to_obsidian:
        try:
            OBSIDIAN_DIR.mkdir(parents=True, exist_ok=True)
            obsidian_path = Path(shutil.copy2(md_path, OBSIDIAN_DIR / md_path.name))
        except Exception:
            obsidian_path = None
    return html_path, md_path, obsidian_path


# ---------- タブ ----------

class ReportTab:
    COLUMNS = (("file", "ファイル", 260), ("label", "ラベル", 90), ("time", "計測日時", 140),
               ("single", "単一Mbps", 90), ("parallel", "6並列Mbps", 90), ("bb", "バッファブロート", 110))

    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.files = []
        self.last_html = None

        top = ttk.Frame(parent, padding=(4, 12))
        top.pack(fill="x")
        ttk.Button(top, text="↻  一覧を更新", command=self.refresh_files).grid(row=0, column=0, padx=(0, 8))
        self.gen_btn = ttk.Button(top, text="📄  HTMLレポート生成", style="Accent.TButton", command=self.generate)
        self.gen_btn.grid(row=0, column=1, padx=(0, 8))
        self.open_btn = ttk.Button(top, text="🌐  ブラウザで開く", command=self.open_in_browser, state="disabled")
        self.open_btn.grid(row=0, column=2, padx=(0, 8))
        self.obsidian_var = tk.BooleanVar(value=OBSIDIAN_DIR.parent.exists())
        ttk.Checkbutton(top, text="Obsidianの診断レポートフォルダにもMarkdownをコピー",
                        variable=self.obsidian_var).grid(row=0, column=3, padx=(4, 0))

        ttk.Label(parent, text="レポート化する結果を1つ選択（Ctrl+クリックで2つ選ぶと前後比較になります。古い方がA/新しい方がB）",
                  foreground="#888", padding=(4, 0, 4, 6)).pack(fill="x")

        self.tree = ttk.Treeview(parent, columns=[c[0] for c in self.COLUMNS], show="headings",
                                 selectmode="extended", height=14)
        for key, head, width in self.COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=4, pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_hint())

        self.status = ttk.Label(parent, text="", padding=(4, 0, 4, 10))
        self.status.pack(fill="x")
        self._status_key = "muted"

        self.refresh_files()

    # --- public契約 ---

    def refresh_files(self):
        keep = {self.tree.item(i, "values")[0] for i in self.tree.selection()} if self.tree.get_children() else set()
        self.tree.delete(*self.tree.get_children())
        # results/ にはLANスキャン等の別機能のJSONも置かれるので診断結果だけ拾う
        loaded = [(p, self._load_safe(p)) for p in nd.list_result_files()]
        loaded = [(p, r) for p, r in loaded if is_diag_result(r)]
        self.files = [p for p, _ in loaded]
        for i, (path, r) in enumerate(loaded):
            thr, bb = (r.get("throughput") or {}), (r.get("bufferbloat") or {})
            self.tree.insert("", "end", iid=str(i), values=(
                path.name, label_of(r), fmt_ts(r.get("timestamp")),
                fmt(g(thr, "single", "mbps"), digits=2), fmt(g(thr, "parallel6", "mbps"), digits=2),
                fmt(bb.get("increase_pct"), "%")))
            if path.name in keep:
                self.tree.selection_add(str(i))
        if not self.files:
            self._set_status("results/ に診断結果JSONがありません。フル診断を実行してください。", "warn")
        else:
            self._update_hint()

    def on_theme_changed(self):
        self._set_status(self.status.cget("text"), self._status_key)

    def on_close(self):
        pass

    # --- 内部 ---

    @staticmethod
    def _load_safe(path):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _set_status(self, text, key="muted"):
        self._status_key = key
        self.status.config(text=text, foreground=self.ctx.theme.get(key, self.ctx.theme["muted"]))

    def _selected_paths(self):
        # 表示は新しい順なので、index降順 = 古い順(A→B)
        idxs = sorted((int(i) for i in self.tree.selection()), reverse=True)
        return [self.files[i] for i in idxs if 0 <= i < len(self.files)]

    def _update_hint(self):
        paths = self._selected_paths()
        if len(paths) == 1:
            self._set_status(f"単体レポート: {paths[0].name}", "muted")
        elif len(paths) == 2:
            self._set_status(f"前後比較: A={paths[0].name} → B={paths[1].name}", "muted")
        elif len(paths) > 2:
            self._set_status(f"{len(paths)}件選択中です。1つ（単体）か2つ（前後比較）にしてください。", "warn")
        else:
            self._set_status("レポート化する結果を選択してください。", "muted")

    def generate(self):
        paths = self._selected_paths()
        if not 1 <= len(paths) <= 2:
            self._set_status("1つ（単体）または2つ（前後比較）を選択してください。", "bad")
            return
        self.gen_btn.config(state="disabled")
        self._set_status("レポート生成中...", "muted")
        to_obsidian = self.obsidian_var.get()

        def worker():
            try:
                html_path, md_path, obs = write_report(paths, copy_to_obsidian=to_obsidian)
                msg = f"✓ 生成: {html_path.name} / {md_path.name}"
                msg += f"  → Obsidianへコピー済み" if obs else ("  （Obsidianへのコピーに失敗）" if to_obsidian else "")
                self.ctx.root.after(0, lambda: self._done(html_path, msg))
            except Exception as e:
                traceback.print_exc()
                self.ctx.root.after(0, lambda: self._fail(f"エラー: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _done(self, html_path, msg):
        self.last_html = html_path
        self.open_btn.config(state="normal")
        self.gen_btn.config(state="normal")
        self._set_status(msg, "good")

    def _fail(self, msg):
        self.gen_btn.config(state="normal")
        self._set_status(msg, "bad")

    def open_in_browser(self):
        if self.last_html and self.last_html.exists():
            webbrowser.open(self.last_html.as_uri())


# ---------- 自己テスト (欠損データ耐性) ----------

def _selftest():
    full = {
        "label": "full", "timestamp": "2026-08-23T19:46:18",
        "ipv6": {"global_addresses": ["2400::1"], "has_global_address": True,
                 "has_default_route": True, "egress_reachable": True},
        "gateway_ip": "192.168.3.1",
        "latency": {"gateway": {"loss_pct": 0, "min_ms": 1, "max_ms": 9, "avg_ms": 2},
                    "1.1.1.1": {"loss_pct": 0, "min_ms": 7, "max_ms": 15, "avg_ms": 8}},
        "traceroute": {"1.1.1.1": [
            {"hop": 1, "ip": "192.168.3.1", "avg_ms": 3.3, "timeout": False, "ip_info": None},
            {"hop": 2, "ip": "221.110.222.210", "avg_ms": 6.0, "timeout": False,
             "ip_info": {"org": "AS17676 SoftBank Corp.", "city": "Tokyo", "country": "JP"}},
            {"hop": 3, "ip": None, "avg_ms": None, "timeout": True}]},
        "public_ip_info": {"ip": "203.0.113.9", "org": "AS17676 SoftBank Corp.", "city": "Tokyo"},
        "dns": {"router": {"avg_ms": 13.5, "min_ms": 11.4, "max_ms": 15.4, "trials_ok": 5, "trials_total": 5},
                "1.1.1.1": {"avg_ms": 14.7, "trials_ok": 5, "trials_total": 5}},
        "throughput": {"single": {"mbps": 257.97}, "parallel6": {"mbps": 412.75, "streams": 6}},
        "bufferbloat": {"idle_latency": {"avg_ms": 6, "max_ms": 7, "loss_pct": 0},
                        "loaded_latency": {"avg_ms": 16, "max_ms": 26, "loss_pct": 10},
                        "increase_ms": 10, "increase_pct": 166.7, "rpm_approx": 3750, "rpm_note": "近似値です"},
    }
    # public_ip_info / ip_info なし、throughput が error、dns/latency 値 None、traceroute が error dict
    broken = {
        "label": "壊れ<データ>&", "timestamp": None,
        "latency": {"gateway": {"loss_pct": 100, "avg_ms": None, "max_ms": None}},
        "traceroute": {"8.8.8.8": {"error": "tracert失敗"}},
        "dns": {"router": {"avg_ms": None, "trials_ok": 0, "trials_total": 5}},
        "throughput": {"single": {"error": "HTTP 429"}, "parallel6": {}},
        "bufferbloat": {},
    }
    empty = {}

    for r in (full, broken, empty, {"label": "x", "ipv6": None, "throughput": None, "dns": None,
                                    "traceroute": None, "bufferbloat": None, "public_ip_info": None}):
        h = build_html([r])
        assert h.startswith("<!DOCTYPE html>") and "<meta charset=\"utf-8\">" in h
        assert "</svg>" in h and "prefers-color-scheme: dark" in h
        assert build_markdown([r], "x.html").startswith("---")

    # 欠損側は「測定失敗」表示になり、例外にならない
    assert "測定失敗" in build_html([broken])
    # ラベルのHTMLエスケープ
    assert "壊れ&lt;データ&gt;&amp;" in build_html([broken])
    # SVGの座標が有限値であること(nan/infが混ざるとブラウザで潰れる)
    svg = throughput_chart(full)
    assert '="nan"' not in svg and '="inf"' not in svg and svg.count("<rect") >= 4
    assert '>250 Mbps<' in svg and '>1000 Mbps<' in svg, "目盛りラベルが壊れている"
    assert ">257.97 Mbps<" in svg
    assert nice_max(34.7) == 40 and nice_max(1000) == 1000 and nice_max(0) == 1.0 and nice_max(17.3) == 20

    # 判定方向はキー名の完全一致ではなく単位・語で推定する (nd.flatten_metrics は項目が増減するため)
    assert direction("下り単一Mbps") == 1 and direction("上り6並列Mbps") == 1
    assert direction("MOS値") == 1 and direction("簡易RPM近似値") == 1
    assert direction("遅延(GW)平均ms") == -1 and direction("ジッターms") == -1
    assert direction("TCP再送率%") == -1 and direction("バッファブロート 負荷時損失%") == -1
    assert direction("NATタイプ") == 0 and direction("ISP") == 0 and direction("通話品質") == 0

    # 前後比較: 欠損だらけの相手でも落ちない / 改善・悪化が正しく色分けされる
    assert diff_rows(full, broken)
    faster = json.loads(json.dumps(full))
    faster["throughput"]["single"]["mbps"] = 500.0
    faster["latency"]["1.1.1.1"]["avg_ms"] = 20
    rows = {r[0]: r for r in diff_rows(full, faster)}
    dl = next(r for k, r in rows.items() if "単一Mbps" in k)
    lat = next(r for k, r in rows.items() if "1.1.1.1" in k and "ms" in k)
    assert dl[4] == "改善" and "%" in dl[3], dl
    assert lat[4] == "悪化", lat
    assert "🔴 悪化" in build_markdown([full, faster])
    assert "class=\"diff\"" in build_html([full, faster])

    # 上り(後から追加された項目)は、ある時だけ行が増える
    with_up = json.loads(json.dumps(full))
    with_up["upload"] = {"single": {"mbps": 120.5}, "parallel6": {"mbps": 180.0}}
    assert "上り 6並列" in throughput_chart(with_up)
    assert "上り" not in throughput_chart(full)

    # 単一の値が None でも棒グラフが壊れない
    assert "測定失敗" in svg_bars([{"label": "a", "value": None}])
    assert safe_label("before after/2") == "before_after_2"

    # results/ に混在する他機能(LANスキャン)のJSONは一覧に出さない
    assert is_diag_result(full) and is_diag_result(broken)
    assert not is_diag_result({"timestamp": "2026-08-23T20:50:25", "range": "192.168.3.0/24", "devices": []})
    assert not is_diag_result([]) and not is_diag_result({})
    print("report_tab selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit(0)

    import tkinter as tk
    from tkinter import ttk
    import sv_ttk
    root = tk.Tk(); root.geometry("900x600"); sv_ttk.set_theme("dark")
    class Ctx: pass
    ctx = Ctx(); ctx.root = root; ctx.font = "Segoe UI"
    ctx.theme = {"bg":"#1c1c1c","card_bg":"#2b2b2b","fg":"#f2f2f2","muted":"#9d9d9d",
                 "good":"#3fb950","warn":"#e3b341","bad":"#f85149",
                 "graph_bg":"#232323","graph_grid":"#3a3a3a"}
    frame = ttk.Frame(root); frame.pack(fill="both", expand=True)
    tab = ReportTab(frame, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
