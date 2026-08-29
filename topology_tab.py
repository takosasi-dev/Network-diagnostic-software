#!/usr/bin/env python3
"""ネットワーク構成図の自動生成タブ。

このPCから見えるものだけを集めて階層図を組み立てる:
  インターネット → ISP(traceroute上流) → 公開IP → ゲートウェイ → LAN機器 → このPC

意図的にやらないこと:
  L3(IP)から見えるのは「同じサブネットに誰がいるか」だけで、**誰が誰にぶら下がっているか**は分からない。
  中継器・AP・スイッチは全部同一サブネットに現れるので、ゲートウェイとLAN機器の間に実線を引くのは嘘になる。
  よってLAN側の区間は全て破線＋「不明」と明記し、断定しない。これがこのモジュールの正しさの核。

描画は tk.Canvas への自前描画。Canvas と SVG が食い違わないよう、いったん共通の
プリミティブ列(scene)を組んでから2つのレンダラに流す。
"""
import ipaddress
import json
import re
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import ttk

import lanscan_tab as ls
import network_diag as nd
from settings_store import settings

MAX_HOPS = 5          # traceroute で見る上流。深くしても図が縦に伸びるだけ
MAX_ISP_NODES = 3     # 図に載せる上流ホップ数の上限
VENDOR_API_LIMIT = 10  # ponytail: 未知OUIのAPI照会は1.5秒間隔なので上限を切る。全件欲しければLANスキャンタブを使う
DNS_WORKERS = 16

# ---- 描画定数 ----
PAD = 16
NODE_W, NODE_H = 200, 68
OVAL_W, OVAL_H = 272, 56
HEX_W, HEX_H = 200, 44
WAN_GAP = 32          # WAN段の縦の間隔(リンク線＋ラベルの分)
BUS_OFFSET = 38       # ゲートウェイ下端からLANバス1本目まで
ROW_GAP = 38          # LANの段と段の間隔
BUS_DROP = 22         # バス線からノード上端まで
LAN_GAP = 14          # LANノードの横間隔
LAN_INSET = 28        # トランク線からノード左端まで
MIN_W = 620
LEGEND_ROW_H = 17

# 種別ごとの色。塗りは theme["card_bg"] を使うので、枠と見出しバーの色だけ持つ。
KIND_COLOR = {
    "internet": "#5aa0d6",
    "isp": "#8a7fd0",
    "public": "#4fb3a5",
    "router": None,      # theme["warn"]
    "netdev": "#e07b39",
    "device": None,      # theme["muted"]
    "self": None,        # theme["good"]
    "unknown": "#8d8d8d",
}
KIND_LABEL = {
    "internet": "インターネット", "isp": "ISP経路", "public": "公開IP(WAN側)",
    "router": "ゲートウェイ(ルーター)", "netdev": "ネットワーク機器の可能性",
    "device": "LAN端末", "self": "このPC", "unknown": "不明",
}

# ネットワーク機器メーカー。ここに当たっても「ルーターだ」とは断定できない(NECはPCも作る)ので、
# 図では必ず「可能性」と書く。
NET_VENDOR_RE = re.compile(
    r"nec|aterm|buffalo|tp[\s\-]?link|elecom|i[\-\s]?o\s?data|iodata|logitec|planex|corega|"
    r"asustek|netgear|d[\-\s]?link|cisco|ubiquiti|aruba|mikrotik|yamaha|allied\s?telesis|"
    r"arris|technicolor|sercomm|zyxel|sagemcom|humax|netcomm|fxc|silex", re.I)

LAN_CAVEAT = "この下の接続順序・有線/無線は測定できません(全て同一サブネットのため)"
CAPTION_LINES = [
    "■破線の区間は「接続関係が測定できない」ことを表します。実線は経路として観測できた区間です。",
    "■LAN内の機器は全て同じサブネットに見えるため、中継器・AP・スイッチが「どの機器の下にいるか」は",
    "　IP層からは判別できません。ここに描かれた横並びは物理的な接続順序ではありません。",
    "■ベンダー名によるネットワーク機器の判定はあくまで推定です(同じメーカーのPC/家電の可能性があります)。",
]


# ============================ 収集 (GUI非依存) ============================

def _ps_json(command, timeout=25):
    """PS 5.1 の ConvertTo-Json は要素1個の配列をオブジェクトに潰すので、必ずリストで返す。"""
    try:
        out = nd.ps(command, timeout=timeout)
    except Exception:
        return []
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


PS_ADAPTERS = (
    "$r=@(); foreach($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
    "Where-Object Status -eq 'Up')){ "
    "$ips=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | "
    "ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }); "
    "$mtu=@(Get-NetIPInterface -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | "
    "Select-Object -ExpandProperty NlMtu); "
    "$r += [pscustomobject]@{Name=$a.Name; Description=$a.InterfaceDescription; "
    "LinkSpeed=$a.LinkSpeed; MediaType=$a.MediaType; PhysicalMediaType=$a.PhysicalMediaType; "
    "FullDuplex=$a.FullDuplex; MacAddress=$a.MacAddress; Mtu=($mtu | Select-Object -First 1); "
    "IPs=$ips} }; $r | ConvertTo-Json -Compress -Depth 4"
)

PS_ROUTES = (
    "@(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object "
    "{ $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | "
    "Sort-Object RouteMetric | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric) "
    "| ConvertTo-Json -Compress"
)


def media_label(media, phys):
    """Get-NetAdapter の MediaType / PhysicalMediaType から有線/無線を判定する。"""
    s = f"{media or ''} {phys or ''}".lower()
    if "802.11" in s or "wireless" in s or "wlan" in s or "wi-fi" in s:
        return "無線"
    if "802.3" in s or "ethernet" in s:
        return "有線"
    return "不明"


def collect_interfaces():
    out = []
    for a in _ps_json(PS_ADAPTERS):
        ips = a.get("IPs") or []
        if isinstance(ips, str):
            ips = [ips]
        out.append({
            "name": a.get("Name") or "", "description": a.get("Description") or "",
            "link_speed": a.get("LinkSpeed") or "", "media": media_label(a.get("MediaType"), a.get("PhysicalMediaType")),
            "media_raw": f"{a.get('MediaType') or ''} / {a.get('PhysicalMediaType') or ''}",
            "duplex": a.get("FullDuplex"), "mac": (a.get("MacAddress") or "").replace("-", ":").lower(),
            "mtu": a.get("Mtu"), "ips": [str(i) for i in ips],
        })
    return out


def collect_routes():
    return [{"prefix": r.get("DestinationPrefix"), "next_hop": r.get("NextHop"),
             "interface": r.get("InterfaceAlias"), "metric": r.get("RouteMetric")}
            for r in _ps_json(PS_ROUTES)]


def classify_device(ip, mac="", vendor="", hostname="", gateway=None, local_ip=None):
    """機器種別の推定。ベンダー名一致は「可能性」であって断定ではない。"""
    if local_ip and ip == local_ip:
        return "self"
    if gateway and ip == gateway:
        return "router"
    if NET_VENDOR_RE.search(f"{vendor or ''} {hostname or ''}"):
        return "netdev"
    return "device"


def target_network(local_ip, net):
    """広すぎるレンジは事故なので /24 に丸める。"""
    if net is None or net.num_addresses > ls.MAX_HOSTS:
        return ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return net


def sweep_lan(net, workers, timeout_ms, stop, progress):
    """並列pingでARPテーブルを埋めつつ生存ホストを集める。生死は 'TTL=' の有無で見る(lanscan_tab と同じ理由)。"""
    hosts = [str(h) for h in net.hosts()]
    alive = {}
    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    futures = {pool.submit(ls.ping_once, ip, timeout_ms): ip for ip in hosts}
    done = 0
    try:
        for fut in as_completed(futures):
            done += 1
            if stop.is_set():
                break
            ms = fut.result()
            if ms is not None:
                alive[futures[fut]] = ms
            if done % 8 == 0 or done == len(hosts):
                progress(f"LAN探索 {done}/{len(hosts)} … {len(alive)}台", 0.1 + 0.5 * done / max(1, len(hosts)))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return alive


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return False


def collect_upstream(target, stop):
    """WAN側の最初の数ホップ。プライベートIP(=自宅内)のホップは上流ではないので落とす。"""
    hops = nd.measure_traceroute(target, max_hops=MAX_HOPS)
    if not isinstance(hops, list):
        return []
    out = []
    for h in hops:
        if stop.is_set():
            break
        ip = h.get("ip")
        if ip and _is_private(ip):
            continue   # 自宅内のホップは上流ではない
        if not ip and not h.get("timeout"):
            continue
        out.append({"hop": h.get("hop"), "ip": ip, "avg_ms": h.get("avg_ms"),
                    "timeout": bool(h.get("timeout")), "org": None})
    return out[:MAX_ISP_NODES]


def build_topology(stop, progress=lambda msg, frac: None):
    """収集 → 推定 まで。ワーカースレッドから呼ぶこと。"""
    workers = settings.get("lanscan.ping_workers")
    timeout_ms = settings.get("lanscan.ping_timeout_ms")
    vendor_on = settings.get("lanscan.vendor_lookup")
    ipinfo_on = settings.get("advanced.ipinfo_enabled")

    topo = {"timestamp": datetime.now().isoformat(timespec="seconds"), "notes": []}

    progress("インタフェース情報を取得中 …", 0.02)
    topo["interfaces"] = collect_interfaces()
    topo["routes"] = collect_routes()
    topo["gateway"] = nd.get_default_gateway()
    topo["gateway_v6"] = next((r["next_hop"] for r in topo["routes"]
                               if r.get("prefix") == "::/0" and r.get("next_hop")), None)

    try:
        local_ip, net = ls.local_ipv4_network()
    except Exception:
        local_ip, net = None, None
    net = target_network(local_ip or "192.168.1.1", net)
    topo["local_ip"] = local_ip
    topo["subnet"] = str(net)

    if stop.is_set():
        return topo
    progress("LAN探索を開始 …", 0.08)
    alive = sweep_lan(net, workers, timeout_ms, stop, progress)
    if topo["gateway"] and topo["gateway"] not in alive:
        alive[topo["gateway"]] = None   # 応答しなくてもゲートウェイは存在する

    progress("ARPテーブルを取得中 …", 0.62)
    arp = ls.get_arp_table()
    devices = []
    for ip in sorted(alive, key=lambda x: int(ipaddress.ip_address(x))):
        mac = arp.get(ip, "")
        devices.append({"ip": ip, "mac": mac, "vendor": ls.vendor_from_table(mac),
                        "hostname": "", "rtt_ms": alive[ip], "kind": "device"})

    if devices and not stop.is_set():
        progress("ホスト名を逆引き中 …", 0.68)
        ips = [d["ip"] for d in devices]
        with ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
            for d, name in zip(devices, ex.map(ls._reverse_dns, ips)):
                d["hostname"] = name or ""

    if vendor_on and not stop.is_set():
        unknown = [d for d in devices if d["mac"] and not d["vendor"]][:VENDOR_API_LIMIT]
        for i, d in enumerate(unknown):
            if stop.is_set():
                break
            progress(f"MACベンダー照会中 {i + 1}/{len(unknown)} …", 0.70 + 0.1 * i / max(1, len(unknown)))
            oui = ls.oui_of(d["mac"])
            if oui in ls._vendor_cache:
                d["vendor"] = ls._vendor_cache[oui]
                continue
            name = ls.lookup_vendor_api(d["mac"])
            if name is not None:
                ls._vendor_cache[oui] = name
                d["vendor"] = name
            stop.wait(ls.VENDOR_API_INTERVAL_S)
        if len(unknown) == VENDOR_API_LIMIT:
            topo["notes"].append(f"MACベンダー照会は{VENDOR_API_LIMIT}件までに制限しています(APIのレート制限のため)。")

    for d in devices:
        d["kind"] = classify_device(d["ip"], d["mac"], d["vendor"], d["hostname"],
                                    gateway=topo["gateway"], local_ip=local_ip)
    topo["devices"] = devices

    if not stop.is_set():
        progress("上流経路を測定中 …", 0.82)
        topo["upstream"] = collect_upstream(settings.get("targets.primary") or "1.1.1.1", stop)
    else:
        topo["upstream"] = []

    topo["public"] = None
    if ipinfo_on and not stop.is_set():
        progress("公開IP / 組織名を照会中 …", 0.92)
        topo["public"] = nd.lookup_ip_info()
        for h in topo["upstream"]:
            if h.get("ip"):
                info = nd.lookup_ip_info(h["ip"])
                h["org"] = (info or {}).get("org")
    else:
        topo["notes"].append("ipinfo.io が無効なため、組織名(ISP名)は表示されません。")

    topo["self_interface"] = next(
        (i for i in topo["interfaces"] if local_ip and any(x.startswith(local_ip + "/") for x in i["ips"])), None)
    progress("完了", 1.0)
    return topo


def derive_caveats(topo):
    """収集結果から「言えること / 言えないこと」を文章にする。build_graph から呼ぶ純関数。"""
    out = list(topo.get("notes") or [])
    devices = topo.get("devices") or []
    cands = [d for d in devices if d.get("kind") == "netdev"]
    if cands:
        names = "、".join(f"{d['ip']}({d.get('vendor') or 'ベンダー不明'})" for d in cands[:4])
        out.append(
            f"ゲートウェイ以外にネットワーク機器メーカーのMACを持つ機器が{len(cands)}台あります: {names}。"
            "中継器 / AP / ブリッジ / 別ルーターの可能性がありますが、IP層からは区別できません。")
    if len(cands) + (1 if topo.get("gateway") else 0) >= 2:
        out.append("ルーター的な機器が複数ある構成に見えます。中継器モードやブリッジ接続の機器は"
                   "ゲートウェイと同じサブネットに現れるため、どれがどの経路上にいるかは判定できません。")
    dead = [h for h in (topo.get("upstream") or []) if not h.get("ip")]
    if dead:
        out.append(f"上流ホップのうち{len(dead)}個はICMPを返しませんでした(ホップ "
                   + "、".join(str(h.get("hop")) for h in dead)
                   + ")。図には出していませんが、その位置に機器は存在します。")
    si = topo.get("self_interface")
    if si:
        out.append(f"このPCの接続は「{si.get('media') or '不明'}」です({si.get('description') or '-'} / "
                   f"{si.get('link_speed') or '-'})。ただし対向がどの機器かは測定できません。")
    return out


# ============================ グラフ組み立て ============================

def _node(nid, kind, title, lines, detail, w=NODE_W, h=NODE_H, shape="rect", link_label="", link_dash=False):
    return {"id": nid, "kind": kind, "title": title, "lines": lines, "detail": detail,
            "w": w, "h": h, "shape": shape, "link_label": link_label, "link_dash": link_dash}


def _fmt_ms(v):
    if v is None:
        return None
    return f"{v:.1f} ms" if isinstance(v, float) else f"{v} ms"


def build_graph(topo):
    """topo -> {"wan": [上から順のノード], "lan": [ノード], "caveats": [str]}

    WAN側は1段1ノードの一本鎖(=線が交差しない)。LAN側は横並びで、リンクは全て破線。
    """
    wan, lan = [], []
    wan.append(_node("internet", "internet", "インターネット", [], "外部ネットワーク。",
                     w=HEX_W, h=HEX_H, shape="hex"))

    # 応答が無かったホップは箱にしても情報が無いので、図には出さず注意書きに回す
    hops = [h for h in (topo.get("upstream") or []) if h.get("ip")]
    isp_nodes = []
    for i, h in enumerate(hops):
        ip, ms = h["ip"], h.get("avg_ms")
        org = h.get("org") or "組織名 不明"
        lines = [ip, org]
        if ms is not None:
            lines.append(f"RTT {_fmt_ms(ms)}")
        n = _node(f"isp{i}", "isp", f"ホップ {h.get('hop')}", lines[:3],
                  f"種別: ISP経路上のホップ\nIP: {ip}\n組織: {h.get('org') or '不明'}\n"
                  f"このPCからのRTT: {_fmt_ms(ms) or '不明'}\n"
                  "※ tracert が返した中継ルーターです。ICMPを返さない機器は経路に居ても現れません。",
                  w=OVAL_W, h=OVAL_H, shape="oval")
        n["rtt"] = ms
        isp_nodes.append(n)

    # traceroute は近い順に来るので、インターネット直下が最遠ホップになるよう反転する。
    # 区間RTTは反転後の隣接ペアから出す(下側ノードがその上のリンクのラベルを持つ)。
    isp_nodes.reverse()
    for upper, lower in zip(isp_nodes, isp_nodes[1:]):
        if upper["rtt"] is not None and lower["rtt"] is not None:
            lower["link_label"] = f"区間 {abs(upper['rtt'] - lower['rtt']):.1f} ms"
    wan.extend(isp_nodes)

    pub = topo.get("public")
    if pub and pub.get("ip"):
        wan.append(_node("public", "public", "公開IP (WAN側)",
                         [pub["ip"], pub.get("org") or "組織名 不明"],
                         f"種別: 契約回線のグローバルIP\nIP: {pub['ip']}\n組織: {pub.get('org') or '不明'}\n"
                         f"地域: {pub.get('city') or '-'} / {pub.get('region') or '-'} / {pub.get('country') or '-'}\n"
                         "※ ルーター(またはその上流のONU/HGW)のWAN側アドレスです。",
                         w=OVAL_W, h=OVAL_H, shape="oval"))
    else:
        wan.append(_node("public", "unknown", "公開IP 不明", ["取得できませんでした"],
                         "公開IPを取得できませんでした(ipinfo.io が無効か、外部通信に失敗)。",
                         w=OVAL_W, h=OVAL_H, shape="oval"))

    gw = topo.get("gateway")
    gw_dev = next((d for d in topo.get("devices") or [] if d["ip"] == gw), None)
    if gw:
        lines = [gw]
        if gw_dev and gw_dev.get("vendor"):
            lines.append(gw_dev["vendor"])
        if gw_dev and gw_dev.get("rtt_ms") is not None:
            lines.append(f"RTT {gw_dev['rtt_ms']} ms")
        detail = (f"種別: デフォルトゲートウェイ\nIP: {gw}\n"
                  f"MAC: {(gw_dev or {}).get('mac') or '不明'}\n"
                  f"ベンダー: {(gw_dev or {}).get('vendor') or '不明'}\n"
                  f"ホスト名: {(gw_dev or {}).get('hostname') or '-'}\n"
                  f"IPv6ゲートウェイ: {topo.get('gateway_v6') or '-'}\n"
                  "※ このPCの既定経路の出口です。この機器がモデム直結か、"
                  "さらに上流にHGW/ONUがあるかはIP層からは分かりません。")
        wan.append(_node("gateway", "router", "ゲートウェイ", lines[:3], detail, link_label="WAN / NAT境界"))
    else:
        wan.append(_node("gateway", "unknown", "ゲートウェイ 不明", ["既定経路が取れません"],
                         "デフォルトゲートウェイを特定できませんでした。"))

    # ---- LAN側 ----
    order = {"netdev": 0, "device": 1, "self": 2}
    devs = [d for d in (topo.get("devices") or []) if d["ip"] != gw]
    devs.sort(key=lambda d: (order.get(d["kind"], 1), int(ipaddress.ip_address(d["ip"]))))
    for d in devs:
        lines = [d["ip"]]
        if d.get("hostname"):
            lines.append(d["hostname"])
        if d.get("vendor"):
            lines.append(d["vendor"])
        if len(lines) < 3 and d.get("rtt_ms") is not None:
            lines.append(f"RTT {d['rtt_ms']} ms")
        title = KIND_LABEL[d["kind"]]
        if d["kind"] == "netdev":
            title = "ネットワーク機器?"
        detail = (f"種別: {KIND_LABEL[d['kind']]}\nIP: {d['ip']}\nMAC: {d.get('mac') or '不明'}\n"
                  f"ベンダー: {d.get('vendor') or '不明'}\nホスト名: {d.get('hostname') or '-'}\n"
                  f"RTT: {_fmt_ms(d.get('rtt_ms')) or '応答なし'}\n")
        if d["kind"] == "netdev":
            detail += ("※ MACベンダーがネットワーク機器メーカーです。中継器/AP/ブリッジ/別ルーターの\n"
                       "　 可能性がありますが、断定はできません(同メーカーのPCや家電の可能性もあります)。\n"
                       "※ この機器がゲートウェイとこのPCの間にいるかどうかはIP層からは分かりません。")
        elif d["kind"] == "self":
            si = topo.get("self_interface") or {}
            detail += (f"インタフェース: {si.get('description') or '-'}\n"
                       f"リンク速度: {si.get('link_speed') or '-'}\n"
                       f"全二重: {'はい' if si.get('duplex') else ('いいえ' if si.get('duplex') is not None else '-')}\n"
                       f"MTU: {si.get('mtu') or '-'}\n媒体: {si.get('media') or '不明'} ({si.get('media_raw') or '-'})\n"
                       "※ 有線/無線はこのPCのアダプタから分かりますが、対向機器は測定できません。")
        lan.append(_node(f"dev{d['ip']}", d["kind"], title, lines[:3], detail))

    if not any(n["kind"] == "self" for n in lan):
        si = topo.get("self_interface") or {}
        lines = [topo.get("local_ip") or "IP不明"]
        if si.get("link_speed"):
            lines.append(si["link_speed"])
        if si.get("media"):
            lines.append(f"媒体: {si['media']}")
        lan.append(_node("self", "self", "このPC", lines[:3],
                         f"種別: このPC\nIP: {topo.get('local_ip') or '不明'}\n"
                         f"インタフェース: {si.get('description') or '-'}\n"
                         f"リンク速度: {si.get('link_speed') or '-'}\nMTU: {si.get('mtu') or '-'}\n"
                         f"媒体: {si.get('media') or '不明'}"))

    return {"wan": wan, "lan": lan, "caveats": derive_caveats(topo)}


# ============================ レイアウト ============================

LEGEND_KINDS = ("internet", "isp", "public", "router", "netdev", "device", "self")


def legend_layout(W):
    """凡例の配置。幅が足りなければ折り返す。段数は図の高さ計算にも使う。"""
    items, x, row = [], PAD + 6, 0
    for k in LEGEND_KINDS:
        wpx = 15 + est_px(KIND_LABEL[k], 8) + 16
        if x + wpx > W - PAD and x > PAD + 6:
            row += 1
            x = PAD + 6
        items.append((k, x, row))
        x += wpx
    return items, row + 1


def layout(graph, width):
    """ノード矩形とバス線の座標を決める。返り値の boxes は id -> (x0,y0,x1,y1)。

    WAN段は1段1ノードで中央揃え(=垂直一直線)。LAN段は左端のトランク線から
    段ごとに横バスを伸ばし、そこから各ノードへ真下に降ろす。よって線は交差しない。
    """
    W = max(int(width or 0), MIN_W)
    boxes = {}
    y = PAD
    for n in graph["wan"]:
        x0 = round((W - n["w"]) / 2)
        boxes[n["id"]] = (x0, y, x0 + n["w"], y + n["h"])
        y += n["h"] + WAN_GAP
    last_bottom = y - WAN_GAP if graph["wan"] else PAD

    trunk_x = PAD + 12
    rows = []
    lan = graph["lan"]
    if lan:
        avail = W - trunk_x - LAN_INSET - PAD
        per_row = max(1, int(avail // (NODE_W + LAN_GAP)))
        for r in range(0, len(lan), per_row):
            chunk = lan[r:r + per_row]
            bus_y = last_bottom + BUS_OFFSET + (r // per_row) * (NODE_H + ROW_GAP)
            ids = []
            for i, n in enumerate(chunk):
                x0 = trunk_x + LAN_INSET + i * (NODE_W + LAN_GAP)
                top = bus_y + BUS_DROP
                boxes[n["id"]] = (x0, top, x0 + n["w"], top + n["h"])
                ids.append(n["id"])
            rows.append({"bus_y": bus_y, "ids": ids})
        bottom = rows[-1]["bus_y"] + BUS_DROP + NODE_H
    else:
        bottom = last_bottom

    caption_y = bottom + 26
    _, legend_rows = legend_layout(W)
    height = caption_y + legend_rows * LEGEND_ROW_H + 8 + len(CAPTION_LINES) * 14 + PAD
    return {"W": W, "H": int(height), "boxes": boxes, "rows": rows, "trunk_x": trunk_x,
            "wan_bottom": last_bottom, "caption_y": caption_y, "legend_rows": legend_rows}


# ============================ テキスト幅 ============================

def text_w(s):
    """半角換算の文字幅。日本語は2でカウントする。"""
    return sum(2 if ord(c) > 0x2E80 else 1 for c in s)


def est_px(s, size):
    """tkフォントサイズ size のときのおおよそのピクセル幅。SVGにも同じ係数を使う。"""
    return text_w(s) * 0.62 * size


def fit(s, box_w, size, ratio=1.0):
    """box_w に収まるよう末尾を落とす。Canvas と SVG で同じ結果になるよう自前で計算する。"""
    budget = max(4, int((box_w * ratio - 18) / (0.62 * size)))
    if text_w(s) <= budget:
        return s
    out, used = "", 0
    for c in s:
        cw = 2 if ord(c) > 0x2E80 else 1
        if used + cw > budget - 1:
            break
        out += c
        used += cw
    return out + "…"


# ============================ シーン(描画プリミティブ) ============================

def _kind_color(kind, theme):
    return KIND_COLOR.get(kind) or {"router": theme["warn"], "device": theme["muted"],
                                    "self": theme["good"]}.get(kind, theme["muted"])


def _hex_points(x0, y0, x1, y1):
    cy = (y0 + y1) / 2
    return [(x0 + 18, y0), (x1 - 18, y0), (x1, cy), (x1 - 18, y1), (x0 + 18, y1), (x0, cy)]


def build_scene(graph, lay, theme, selected=None):
    """Canvas と SVG の両方に流す共通プリミティブ列を作る。"""
    s = []
    B = lay["boxes"]
    dash_col = theme["muted"]

    def line(x0, y0, x1, y1, col, w=1, dash=False):
        s.append({"t": "line", "x0": x0, "y0": y0, "x1": x1, "y1": y1, "fill": col, "w": w, "dash": dash})

    def text(x, y, string, col, size=8, anchor="w", bold=False):
        s.append({"t": "text", "x": x, "y": y, "s": string, "fill": col, "size": size,
                  "anchor": anchor, "bold": bold})

    # ---- WAN段のリンク(中央の一直線) ----
    wan = graph["wan"]
    for upper, lower in zip(wan, wan[1:]):
        ux0, uy0, ux1, uy1 = B[upper["id"]]
        lx0, ly0, lx1, ly1 = B[lower["id"]]
        cx = (ux0 + ux1) / 2
        line(cx, uy1, cx, ly0, theme["fg"], 1, lower["link_dash"])
        if lower["link_label"]:
            text(cx + 10, (uy1 + ly0) / 2, lower["link_label"], theme["muted"], 8, "w")

    # ---- LAN側: トランク＋バス(全て破線=不明) ----
    rows = lay["rows"]
    if rows and wan:
        gx0, gy0, gx1, gy1 = B[wan[-1]["id"]]
        gcx = (gx0 + gx1) / 2
        elbow_y = gy1 + 16
        tx = lay["trunk_x"]
        line(gcx, gy1, gcx, elbow_y, dash_col, 1, True)
        line(gcx, elbow_y, tx, elbow_y, dash_col, 1, True)
        line(tx, elbow_y, tx, rows[-1]["bus_y"], dash_col, 1, True)
        text(tx + 8, elbow_y + 13, LAN_CAVEAT, theme["warn"], 8, "w")
        for row in rows:
            xs = [B[i] for i in row["ids"]]
            line(tx, row["bus_y"], max(b[2] for b in xs), row["bus_y"], dash_col, 1, True)
            for nid in row["ids"]:
                bx0, by0, bx1, _ = B[nid]
                cx = (bx0 + bx1) / 2
                line(cx, row["bus_y"], cx, by0, dash_col, 1, True)
                text(cx + 4, (row["bus_y"] + by0) / 2, "不明", dash_col, 7, "w")

    # ---- ノード ----
    for n in wan + graph["lan"]:
        x0, y0, x1, y1 = B[n["id"]]
        col = _kind_color(n["kind"], theme)
        sel = (n["id"] == selected)
        wdt = 3 if sel or n["kind"] == "self" else 1
        if n["shape"] == "hex":
            s.append({"t": "poly", "pts": _hex_points(x0, y0, x1, y1), "fill": theme["card_bg"],
                      "outline": col, "w": wdt})
        elif n["shape"] == "oval":
            s.append({"t": "oval", "x0": x0, "y0": y0, "x1": x1, "y1": y1,
                      "fill": theme["card_bg"], "outline": col, "w": wdt})
        else:
            s.append({"t": "rect", "x0": x0, "y0": y0, "x1": x1, "y1": y1,
                      "fill": theme["card_bg"], "outline": col, "w": wdt, "dash": False})
            s.append({"t": "rect", "x0": x0, "y0": y0, "x1": x1, "y1": y0 + 4,
                      "fill": col, "outline": col, "w": 1, "dash": False})
        if sel:
            s.append({"t": "rect", "x0": x0 - 4, "y0": y0 - 4, "x1": x1 + 4, "y1": y1 + 4,
                      "fill": "", "outline": theme["fg"], "w": 1, "dash": True})

        if n["shape"] in ("hex", "oval"):
            cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
            ratio = 0.72 if n["shape"] == "oval" else 0.80
            rows_txt = [n["title"]] + list(n["lines"])
            top = cy - (len(rows_txt) - 1) * 6.5
            for i, t_ in enumerate(rows_txt):
                text(cx, top + i * 13, fit(t_, n["w"], 9 if i == 0 else 8, ratio),
                     theme["fg"] if i == 0 else theme["muted"], 9 if i == 0 else 8, "center", i == 0)
        else:
            text(x0 + 9, y0 + 16, fit(n["title"], n["w"], 9), theme["fg"], 9, "w", True)
            for i, t_ in enumerate(n["lines"]):
                text(x0 + 9, y0 + 33 + i * 13, fit(t_, n["w"], 8),
                     theme["fg"] if i == 0 else theme["muted"], 8, "w")

    # ---- 凡例 + 注意書き ----
    cy = lay["caption_y"]
    items, nrows = legend_layout(lay["W"])
    for kind, lx, row in items:
        col = _kind_color(kind, theme)
        y = cy + row * LEGEND_ROW_H
        s.append({"t": "rect", "x0": lx, "y0": y - 5, "x1": lx + 10, "y1": y + 5,
                  "fill": col, "outline": col, "w": 1, "dash": False})
        text(lx + 15, y, KIND_LABEL[kind], theme["muted"], 8, "w")
    base_y = cy + nrows * LEGEND_ROW_H + 8
    for i, cap in enumerate(CAPTION_LINES):
        text(PAD + 6, base_y + i * 14, cap, theme["muted"], 8, "w")
    return s


# ============================ レンダラ ============================

def render_canvas(canvas, scene, font="Segoe UI"):
    canvas.delete("all")
    for p in scene:
        t = p["t"]
        if t == "line":
            canvas.create_line(p["x0"], p["y0"], p["x1"], p["y1"], fill=p["fill"], width=p["w"],
                               **({"dash": (4, 3)} if p.get("dash") else {}))
        elif t == "rect":
            canvas.create_rectangle(p["x0"], p["y0"], p["x1"], p["y1"], fill=p["fill"] or "",
                                    outline=p["outline"], width=p["w"],
                                    **({"dash": (3, 3)} if p.get("dash") else {}))
        elif t == "oval":
            canvas.create_oval(p["x0"], p["y0"], p["x1"], p["y1"], fill=p["fill"],
                               outline=p["outline"], width=p["w"])
        elif t == "poly":
            canvas.create_polygon(p["pts"], fill=p["fill"], outline=p["outline"], width=p["w"])
        elif t == "text":
            canvas.create_text(p["x"], p["y"], text=p["s"], fill=p["fill"], anchor=p["anchor"],
                               font=(font, p["size"], "bold") if p["bold"] else (font, p["size"]))


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


_SVG_ANCHOR = {"w": ("start", "central"), "center": ("middle", "central"), "n": ("middle", "hanging")}


def render_svg(scene, width, height, bg):
    """Canvas と同じ scene から SVG を作る。外部ライブラリ不要、そのままブラウザ/Obsidianで開ける。"""
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(width)}" height="{int(height)}" '
           f'viewBox="0 0 {int(width)} {int(height)}" font-family="Segoe UI, Meiryo, sans-serif">',
           f'<rect x="0" y="0" width="{int(width)}" height="{int(height)}" fill="{_esc(bg)}"/>']
    for p in scene:
        t = p["t"]
        if t == "line":
            d = ' stroke-dasharray="4,3"' if p.get("dash") else ""
            out.append(f'<line x1="{p["x0"]:.1f}" y1="{p["y0"]:.1f}" x2="{p["x1"]:.1f}" y2="{p["y1"]:.1f}" '
                       f'stroke="{_esc(p["fill"])}" stroke-width="{p["w"]}"{d}/>')
        elif t == "rect":
            d = ' stroke-dasharray="3,3"' if p.get("dash") else ""
            fill = p["fill"] or "none"
            out.append(f'<rect x="{p["x0"]:.1f}" y="{p["y0"]:.1f}" width="{max(0, p["x1"] - p["x0"]):.1f}" '
                       f'height="{max(0, p["y1"] - p["y0"]):.1f}" fill="{_esc(fill)}" '
                       f'stroke="{_esc(p["outline"])}" stroke-width="{p["w"]}"{d}/>')
        elif t == "oval":
            cx, cy = (p["x0"] + p["x1"]) / 2, (p["y0"] + p["y1"]) / 2
            out.append(f'<ellipse cx="{cx:.1f}" cy="{cy:.1f}" rx="{(p["x1"] - p["x0"]) / 2:.1f}" '
                       f'ry="{(p["y1"] - p["y0"]) / 2:.1f}" fill="{_esc(p["fill"])}" '
                       f'stroke="{_esc(p["outline"])}" stroke-width="{p["w"]}"/>')
        elif t == "poly":
            pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in p["pts"])
            out.append(f'<polygon points="{pts}" fill="{_esc(p["fill"])}" stroke="{_esc(p["outline"])}" '
                       f'stroke-width="{p["w"]}"/>')
        elif t == "text":
            anchor, base = _SVG_ANCHOR.get(p["anchor"], ("start", "central"))
            weight = ' font-weight="bold"' if p["bold"] else ""
            out.append(f'<text x="{p["x"]:.1f}" y="{p["y"]:.1f}" fill="{_esc(p["fill"])}" '
                       f'font-size="{p["size"] * 1.34:.1f}px" text-anchor="{anchor}" '
                       f'dominant-baseline="{base}"{weight}>{_esc(p["s"])}</text>')
    out.append("</svg>")
    return "\n".join(out)


def to_markdown(topo, graph):
    """Obsidianに貼れるツリー版。図と同じ「不明」の書き方を守る。"""
    def row(n):
        return n["title"] + ("  [" + " / ".join(n["lines"]) + "]" if n["lines"] else "")

    L = [f"# ネットワーク構成図 ({topo.get('timestamp', '')})", "", "```", "インターネット"]
    indent = 0
    for n in graph["wan"][1:]:
        indent += 2
        L.append(" " * indent + "└─ " + row(n))
    pad = " " * (indent + 3)
    L.append(pad + "╎")
    L.append(pad + f"╎ ← {LAN_CAVEAT}")
    L.append(pad + f"╎ LAN {topo.get('subnet') or '?'}")
    for n in graph["lan"]:
        L.append(pad + "├─ " + row(n))
    L.append("```")
    L.append("")
    L.append("## 推定できないこと")
    bullets = []   # 図では折り返している行を1つの箇条書きに戻す
    for c in CAPTION_LINES:
        if c.startswith("■") or not bullets:
            bullets.append(c.lstrip("■　"))
        else:
            bullets[-1] += c.lstrip("　")
    L.extend("- " + b for b in bullets)
    if graph["caveats"]:
        L.append("")
        L.append("## このスキャンで分かったこと / 注意")
        for c in graph["caveats"]:
            L.append("- " + c)
    return "\n".join(L) + "\n"


# ============================ タブ本体 ============================

class TopologyTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.topo = None
        self.graph = None
        self.layout = None
        self.scene = []
        self.selected = None
        self._stop = threading.Event()
        self._thread = None
        self._progress = (0.0, "")
        self._poll_job = None

        top = ttk.Frame(parent, padding=(6, 10))
        top.pack(fill="x")
        self.scan_btn = ttk.Button(top, text="▶  構成を自動検出", style="Accent.TButton", command=self.start)
        self.scan_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(top, text="⏹  停止", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 6))
        ttk.Button(top, text="⬇  保存 (JSON / SVG / MD)", command=self.export).pack(side="left", padx=(0, 6))
        ttk.Label(top, text="※ LAN内の接続順序・有線/無線は測定できません(破線の区間)").pack(side="left", padx=(10, 0))

        bar = ttk.Frame(parent, padding=(6, 0))
        bar.pack(fill="x")
        self.progress = ttk.Progressbar(bar, mode="determinate", maximum=1000)
        self.progress.pack(side="left", fill="x", expand=True)
        self.status = ttk.Label(bar, text="「構成を自動検出」で開始します。", width=46, anchor="w")
        self.status.pack(side="left", padx=(10, 0))

        pane = ttk.PanedWindow(parent, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=(6, 8))

        left = ttk.Frame(pane)
        self.canvas = tk.Canvas(left, width=820, height=560, highlightthickness=1, bd=0)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.canvas.bind("<Configure>", lambda e: self.draw())
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        pane.add(left, weight=4)

        right = ttk.Frame(pane)
        ttk.Label(right, text="ノード詳細", padding=(6, 4)).pack(fill="x")
        self.detail = tk.Text(right, width=38, wrap="word", padx=8, pady=8, bd=0,
                              highlightthickness=0, font=(ctx.font, 9))
        self.detail.pack(fill="both", expand=True)
        pane.add(right, weight=1)

        self.on_theme_changed()
        self._set_detail("図の中のノードをクリックすると、ここに詳細が出ます。\n\n"
                         "まず「構成を自動検出」を押してください。")

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        self.canvas.config(bg=t["graph_bg"], highlightbackground=t["graph_grid"])
        self.detail.config(bg=t["card_bg"], fg=t["fg"], insertbackground=t["fg"])
        self.draw()

    # ---- 収集 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        self._poll()

    def stop(self):
        self._stop.set()
        self.stop_btn.config(state="disabled")

    def _worker(self):
        def progress(msg, frac):
            self._progress = (frac, msg)
        try:
            topo = build_topology(self._stop, progress)
        except Exception as e:  # 収集の失敗でGUIを落とさない
            self._progress = (1.0, f"失敗: {e}")
            return
        self.ctx.root.after(0, lambda: self._apply(topo))

    def _apply(self, topo):
        self.topo = topo
        self.graph = build_graph(topo)
        self.selected = None
        self.draw()
        self._progress = (1.0, f"完了: LAN {len(topo.get('devices') or [])}台 / "
                               f"上流 {len(topo.get('upstream') or [])}ホップ")
        caveats = "\n\n".join("・" + c for c in self.graph["caveats"]) or "特記事項なし。"
        self._set_detail("【この図で断定していないこと】\n"
                         + "\n".join(CAPTION_LINES) + "\n\n【検出結果のメモ】\n" + caveats
                         + "\n\nノードをクリックすると詳細が出ます。")

    def _poll(self):
        frac, msg = self._progress
        self.progress.config(value=int(frac * 1000))
        self.status.config(text=msg or "")
        if self._thread and self._thread.is_alive():
            self._poll_job = self.ctx.root.after(200, self._poll)
        else:
            self._poll_job = None
            self.scan_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    # ---- 描画 ----

    def _canvas_width(self):
        w = self.canvas.winfo_width()
        return w if w > 10 else 820   # 初回の <Configure> 前は 1 が返る

    def draw(self):
        if not self.graph:
            self.canvas.delete("all")
            w, h = self._canvas_width(), max(self.canvas.winfo_height(), 200)
            self.canvas.create_text(w / 2, h / 2, text="「構成を自動検出」でこのPCから見える構成を図にします",
                                    fill=self.ctx.theme["muted"], font=(self.ctx.font, 11))
            self.canvas.configure(scrollregion=(0, 0, w, h))
            return
        self.layout = layout(self.graph, self._canvas_width() - 4)
        self.scene = build_scene(self.graph, self.layout, self.ctx.theme, self.selected)
        render_canvas(self.canvas, self.scene, self.ctx.font)
        self.canvas.configure(scrollregion=(0, 0, self.layout["W"], self.layout["H"]))

    def _on_click(self, event):
        if not self.layout:
            return
        x, y = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        for nid, (x0, y0, x1, y1) in self.layout["boxes"].items():
            if x0 <= x <= x1 and y0 <= y <= y1:
                self.selected = nid
                node = next(n for n in self.graph["wan"] + self.graph["lan"] if n["id"] == nid)
                self._set_detail(f"{node['title']}\n{'-' * 30}\n{node['detail']}")
                self.draw()
                return

    def _set_detail(self, text):
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.config(state="disabled")

    # ---- エクスポート ----

    def export(self):
        if not self.topo or not self.graph:
            self.status.config(text="先に「構成を自動検出」を実行してください")
            return
        try:
            nd.RESULTS_DIR.mkdir(exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = nd.RESULTS_DIR / f"topology_{stamp}"
            payload = dict(self.topo)
            payload["undeterminable"] = CAPTION_LINES
            base.with_suffix(".json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            lay = layout(self.graph, self._canvas_width() - 4)
            scene = build_scene(self.graph, lay, self.ctx.theme, None)
            base.with_suffix(".svg").write_text(
                render_svg(scene, lay["W"], lay["H"], self.ctx.theme["graph_bg"]), encoding="utf-8")
            base.with_suffix(".md").write_text(to_markdown(self.topo, self.graph), encoding="utf-8")
        except Exception as e:
            self.status.config(text=f"保存に失敗: {e}")
            return
        self.status.config(text=f"✓ 保存: {base.name}.json / .svg / .md")

    def on_close(self):
        self._stop.set()
        if self._poll_job:
            try:
                self.ctx.root.after_cancel(self._poll_job)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)


# ============================ 自己テスト (ネットワーク不要) ============================

THEME = {"bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
         "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
         "graph_bg": "#232323", "graph_grid": "#3a3a3a"}


def _fake_topo(n_devices=8):
    devs = [{"ip": "192.168.3.1", "mac": "30:f7:72:c9:97:a7", "vendor": "Hon Hai (Foxconn)",
             "hostname": "", "rtt_ms": 1, "kind": "router"},
            {"ip": "192.168.3.12", "mac": "9c:b6:d0:11:22:33", "vendor": "Rivet Networks",
             "hostname": "my-pc", "rtt_ms": 0, "kind": "self"},
            {"ip": "192.168.3.5", "mac": "98:f1:99:8b:66:30", "vendor": "NEC Platforms",
             "hostname": "", "rtt_ms": 2, "kind": "netdev"},
            {"ip": "192.168.3.6", "mac": "1c:61:b4:aa:bb:cc", "vendor": "TP-Link",
             "hostname": "", "rtt_ms": 3, "kind": "netdev"}]
    for i in range(n_devices):
        devs.append({"ip": f"192.168.3.{20 + i}", "mac": f"58:bd:a3:00:00:{i:02x}",
                     "vendor": "Nintendo", "hostname": f"host{i}.lan", "rtt_ms": 4 + i, "kind": "device"})
    return {
        "timestamp": "2026-08-24T12:00:00", "local_ip": "192.168.3.12", "subnet": "192.168.3.0/24",
        "gateway": "192.168.3.1", "gateway_v6": "fe80::1",
        "public": {"ip": "126.1.32.112", "org": "AS17676 SoftBank Corp.", "city": "Tokyo",
                   "region": "Tokyo", "country": "JP"},
        "interfaces": [], "routes": [],
        "self_interface": {"name": "イーサネット", "description": "Killer E3100G 2.5 Gigabit Ethernet",
                           "link_speed": "1 Gbps", "media": "有線", "media_raw": "802.3 / 802.3",
                           "duplex": True, "mac": "9c:b6:d0:11:22:33", "mtu": 1500, "ips": ["192.168.3.12/24"]},
        "upstream": [{"hop": 2, "ip": "221.110.222.210", "avg_ms": 8.6, "timeout": False,
                      "org": "AS17676 SoftBank Corp."},
                     {"hop": 3, "ip": "221.110.222.209", "avg_ms": 9.9, "timeout": False,
                      "org": "AS17676 SoftBank Corp."}],
        "devices": devs, "notes": ["テスト用のメモ"],
    }


def _rects_overlap(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def _check_layout(graph, width):
    lay = layout(graph, width)
    ids = list(lay["boxes"])
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            assert not _rects_overlap(lay["boxes"][a], lay["boxes"][b]), \
                f"ノードが重なっている: {a} {lay['boxes'][a]} / {b} {lay['boxes'][b]} (幅 {width})"
    for nid, (x0, y0, x1, y1) in lay["boxes"].items():
        assert 0 <= x0 < x1 <= lay["W"], f"{nid} が横にはみ出している: {(x0, x1)} / W={lay['W']}"
        assert 0 <= y0 < y1 <= lay["H"], f"{nid} が縦にはみ出している: {(y0, y1)} / H={lay['H']}"
    return lay


def selftest():
    # ---- ARPパース(lanscan_tab の実装を流用しているので、期待どおり動くことをここでも確認する) ----
    arp = ls.parse_arp_table("  192.168.3.1           30-f7-72-c9-97-a7     動的\n"
                             "  192.168.3.16          9C-AE-D3-D5-EC-56     動的\n")
    assert arp == {"192.168.3.1": "30:f7:72:c9:97:a7", "192.168.3.16": "9c:ae:d3:d5:ec:56"}, arp
    assert ls.parse_arp_table("インターフェイス: 192.168.3.12 --- 0x2") == {}

    # ---- 機器種別の推定 ----
    assert classify_device("192.168.3.12", local_ip="192.168.3.12") == "self"
    assert classify_device("192.168.3.1", gateway="192.168.3.1") == "router"
    assert classify_device("192.168.3.1", gateway="192.168.3.1", local_ip="192.168.3.1") == "self"
    for v in ("NEC Platforms", "Buffalo.INC", "TP-LINK TECHNOLOGIES", "tp link", "ASUSTek COMPUTER",
              "I-O DATA DEVICE", "ELECOM", "NETGEAR", "D-Link", "Aterm"):
        assert classify_device("192.168.3.9", vendor=v) == "netdev", v
    for v in ("Nintendo", "Samsung Electronics", "Sharp", "Murata Manufacturing", "Hon Hai (Foxconn)",
              "ランダムMAC(端末が秘匿)", ""):
        assert classify_device("192.168.3.9", vendor=v) == "device", v
    assert classify_device("192.168.3.9", hostname="aterm-1234.lan") == "netdev"

    # ---- 有線/無線判定 ----
    assert media_label("802.3", "802.3") == "有線"
    assert media_label("Native 802.11", "Native 802.11") == "無線"
    assert media_label(None, None) == "不明"
    assert media_label("Unspecified", "BlueTooth") == "不明"

    # ---- レンジの丸め ----
    assert str(target_network("192.168.3.12", ipaddress.ip_network("192.168.0.0/16"))) == "192.168.3.0/24"
    assert str(target_network("192.168.3.12", ipaddress.ip_network("192.168.3.0/24"))) == "192.168.3.0/24"
    assert str(target_network("192.168.3.12", None)) == "192.168.3.0/24"

    # ---- テキストの切り詰め ----
    assert text_w("abc") == 3 and text_w("あい") == 4
    long = "非常に長いベンダー名がここに入りますテストテストテスト"
    assert fit(long, NODE_W, 8) != long and fit(long, NODE_W, 8).endswith("…")
    assert est_px(fit(long, NODE_W, 8), 8) <= NODE_W - 16
    assert fit("192.168.3.1", NODE_W, 8) == "192.168.3.1"
    assert fit("", NODE_W, 8) == ""

    # ---- グラフ構築 + レイアウト ----
    topo = _fake_topo(8)
    g = build_graph(topo)
    assert g["wan"][0]["kind"] == "internet"
    assert [n["kind"] for n in g["wan"]][-2:] == ["public", "router"]
    # traceroute は遠い順に並べ直されていること(ホップ3がホップ2より上)
    isp_titles = [n["title"] for n in g["wan"] if n["kind"] == "isp"]
    assert isp_titles == ["ホップ 3", "ホップ 2"], isp_titles
    # 区間RTTのラベルは「その上のリンク」を表す下側ノードに付く(反転後の隣接ペアで計算)
    isp = [n for n in g["wan"] if n["kind"] == "isp"]
    assert isp[0]["link_label"] == "" and isp[1]["link_label"] == "区間 1.3 ms", \
        [n["link_label"] for n in isp]
    # 応答なしホップは箱にせず注意書きへ回す
    g_dead = build_graph(dict(topo, upstream=topo["upstream"]
                              + [{"hop": 4, "ip": None, "avg_ms": None, "timeout": True, "org": None}]))
    assert len([n for n in g_dead["wan"] if n["kind"] == "isp"]) == 2
    assert any("ICMPを返しません" in c for c in g_dead["caveats"]), g_dead["caveats"]
    kinds = [n["kind"] for n in g["lan"]]
    assert kinds.count("netdev") == 2 and kinds.count("self") == 1
    assert kinds.index("netdev") < kinds.index("device") < kinds.index("self"), kinds
    assert not any(n["id"] == "devgw" for n in g["lan"])
    assert any("中継器" in c for c in g["caveats"]), g["caveats"]
    assert any("複数" in c for c in g["caveats"])

    for width in (MIN_W - 400, 620, 900, 1250, 1900):
        lay = _check_layout(g, width)
        scene = build_scene(g, lay, THEME, selected=None)
        # 文字が箱からはみ出していないこと
        for p in scene:
            if p["t"] != "text":
                continue
            for nid, (x0, y0, x1, y1) in lay["boxes"].items():
                if not (x0 <= p["x"] <= x1 and y0 <= p["y"] <= y1):
                    continue
                half = p["size"] * 0.75   # 文字の上下半分のおおよそ
                assert y0 <= p["y"] - half and p["y"] + half <= y1, \
                    f"{nid} の文字が上下にはみ出している: {p['s']!r} y={p['y']} box={(y0, y1)}"
                w_px = est_px(p["s"], p["size"])
                left = p["x"] if p["anchor"] == "w" else p["x"] - w_px / 2
                assert x0 <= left and left + w_px <= x1 - 2, \
                    f"{nid} の文字が左右にはみ出している: {p['s']!r}"
            assert 0 <= p["x"] <= lay["W"] and 0 <= p["y"] <= lay["H"], p
            if p["anchor"] == "w":   # 左寄せの文字が右端をはみ出していないこと
                assert p["x"] + est_px(p["s"], p["size"]) <= lay["W"], (width, p)

    # ---- 段の割り当て: 幅を狭めると段が増え、広げると減る ----
    narrow = layout(g, 700)
    wide = layout(g, 1900)
    assert len(narrow["rows"]) > len(wide["rows"]), (len(narrow["rows"]), len(wide["rows"]))
    assert sum(len(r["ids"]) for r in narrow["rows"]) == len(g["lan"])
    assert sum(len(r["ids"]) for r in wide["rows"]) == len(g["lan"])
    # 段は必ず下へ進む
    ys = [r["bus_y"] for r in narrow["rows"]]
    assert ys == sorted(ys) and len(set(ys)) == len(ys)
    # WAN段は全て中央揃え(=一直線になる)
    centers = {round((narrow["boxes"][n["id"]][0] + narrow["boxes"][n["id"]][2]) / 2) for n in g["wan"]}
    assert len(centers) == 1, centers

    # ---- 退化ケース: LAN 0台 / 1台 ----
    empty = {"timestamp": "t", "local_ip": None, "subnet": None, "gateway": None, "gateway_v6": None,
             "public": None, "interfaces": [], "routes": [], "self_interface": None,
             "upstream": [], "devices": [], "notes": []}
    g0 = build_graph(empty)
    assert len(g0["lan"]) == 1 and g0["lan"][0]["kind"] == "self", g0["lan"]  # このPCだけは必ず出す
    lay0 = _check_layout(g0, 900)
    assert len(lay0["rows"]) == 1
    s0 = build_scene(g0, lay0, THEME)
    assert render_svg(s0, lay0["W"], lay0["H"], "#232323").endswith("</svg>")

    one = dict(empty, gateway="192.168.3.1", local_ip="192.168.3.12",
               devices=[{"ip": "192.168.3.1", "mac": "", "vendor": "", "hostname": "",
                         "rtt_ms": 1, "kind": "router"}])
    g1 = build_graph(one)
    assert len(g1["lan"]) == 1
    _check_layout(g1, 900)

    # LANノードが全く無い状態でも落ちないこと(内部関数を直接叩く)
    g_no_lan = {"wan": g0["wan"], "lan": [], "caveats": []}
    lay_n = _check_layout(g_no_lan, 900)
    assert lay_n["rows"] == []
    assert "</svg>" in render_svg(build_scene(g_no_lan, lay_n, THEME), lay_n["W"], lay_n["H"], "#232323")

    # ---- SVG ----
    lay = layout(g, 1250)
    svg = render_svg(build_scene(g, lay, THEME), lay["W"], lay["H"], THEME["graph_bg"])
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    for tag in ("rect", "text", "line", "ellipse", "polygon"):
        assert svg.count(f"<{tag}") > 0, f"{tag} が1つも無い"
    assert svg.count("<text") == svg.count("</text>"), "textタグが閉じていない"
    assert 'stroke-dasharray' in svg, "不明区間の破線が出ていない"
    # 数値属性に nan / inf が混ざるとブラウザで図が潰れる
    for m in re.finditer(r'\b(?:x|y|cx|cy|rx|ry|x1|y1|x2|y2|width|height)="([^"]*)"', svg):
        assert re.fullmatch(r"-?\d+(\.\d+)?(px)?", m.group(1)), f"数値でない座標: {m.group(1)!r}"
    # 座標が全てビューポート内であること
    for m in re.finditer(r'(?:x|y|cx|cy|x1|y1|x2|y2)="(-?[\d.]+)"', svg):
        v = float(m.group(1))
        assert -5 <= v <= max(lay["W"], lay["H"]) + 5, f"座標が範囲外: {v}"
    for m in re.finditer(r'points="([^"]+)"', svg):
        for pair in m.group(1).split():
            px, py = (float(t) for t in pair.split(","))
            assert 0 <= px <= lay["W"] and 0 <= py <= lay["H"], (px, py)
    # エスケープ
    assert _esc('<a href="x">&') == "&lt;a href=&quot;x&quot;&gt;&amp;"
    g_esc = build_graph(dict(topo, public={"ip": "1.2.3.4", "org": "A&B <corp>"}))
    assert "&amp;B &lt;corp&gt;" in render_svg(
        build_scene(g_esc, layout(g_esc, 1250), THEME), 1250, 900, "#232323")

    # ---- Markdown ----
    md = to_markdown(topo, g)
    assert md.count("```") == 2 and "推定できないこと" in md
    assert LAN_CAVEAT in md
    assert "192.168.3.0/24" in md

    print("topology selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.title("ネットワーク構成図")
    root.geometry("1250x760")
    sv_ttk.set_theme("dark")

    class Ctx:
        pass

    ctx = Ctx()
    ctx.root = root
    ctx.font = "Segoe UI"
    ctx.theme = dict(THEME)
    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)
    tab = TopologyTab(frame, ctx)
    if "--autostart" in sys.argv:   # 目視確認用: 起動と同時に検出を走らせる
        root.after(600, tab.start)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
