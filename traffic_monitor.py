"""生ソケット(SIO_RCVALL)でこのPC自身のIPv4トラフィックを集計する通信量モニター。
Npcap等の追加ドライバは不要だが、管理者権限とIPv4のみという制約がある:
- 同一スイッチ上の「他の家庭内デバイス」の通信はこのPCからは原理的に見えない(ミラーポートが無い限り)。
- IPv6経由の通信はこの版では捕捉しない(Windowsの生IPv6ソケット挙動が機種依存で不安定なため、まずIPv4のみに絞った)。
"""
import socket
import struct
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

# libpcap形式。SIO_RCVALLで取れるのはEthernetヘッダを含まない生IPパケットなので
# linktypeは 101 (LINKTYPE_RAW)。これで本物のWiresharkがそのまま開ける。
PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE_RAW = 101
PCAP_SNAPLEN = 65535


def pcap_global_header():
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE_RAW)


def pcap_packet_record(data, timestamp):
    sec = int(timestamp)
    usec = int((timestamp - sec) * 1_000_000)
    captured = min(len(data), PCAP_SNAPLEN)
    return struct.pack("<IIII", sec, usec, captured, len(data)) + data[:captured]


def get_local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


class TrafficMonitor:
    def __init__(self):
        self.local_ip = None
        self.stats = {}  # (remote_ip, remote_port, proto_name) -> dict
        self.error = None
        self._stop = threading.Event()
        self._thread = None
        self._proc_thread = None
        self._hostname_cache = {}
        self._resolving = set()
        self.pcap_path = None
        self.pcap_packets = 0
        self._pcap_file = None
        self._pcap_lock = threading.Lock()

    def start(self, pcap_path=None):
        """pcap_path を渡すと、キャプチャしたパケットをlibpcap形式でも書き出す(Wiresharkで開ける)。"""
        self.error = None
        self.stats = {}
        self.pcap_packets = 0
        # ファイルはソケット確保に成功してから開く(権限不足で失敗したとき空pcapを残さないため)
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self._stop.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        self._proc_thread = threading.Thread(target=self._process_mapping_loop, daemon=True)
        self._proc_thread.start()

    def stop(self):
        self._stop.set()
        with self._pcap_lock:  # キャプチャスレッドの書き込み中にcloseしないため
            if self._pcap_file:
                try:
                    self._pcap_file.close()
                except OSError:
                    pass
                self._pcap_file = None

    def _capture_loop(self):
        try:
            self.local_ip = get_local_ipv4()
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self.local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
        except OSError as e:
            self.error = f"キャプチャ開始失敗: {e}\n管理者としてこのプログラムを実行し直してください。"
            self.pcap_path = None
            return

        if self.pcap_path:
            try:
                with self._pcap_lock:
                    self._pcap_file = open(self.pcap_path, "wb")
                    self._pcap_file.write(pcap_global_header())
            except OSError as e:
                self.error = f"pcapファイルを開けません: {e}"
                self.pcap_path = None

        while not self._stop.is_set():
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._write_pcap(data)
            self._handle_packet(data)

        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except OSError:
            pass

    def _write_pcap(self, data):
        if not self._pcap_file:
            return
        try:
            with self._pcap_lock:
                if not self._pcap_file:  # stop()と競合した場合
                    return
                self._pcap_file.write(pcap_packet_record(data, time.time()))
                self.pcap_packets += 1
        except OSError:
            pass

    def _handle_packet(self, data):
        if len(data) < 20:
            return
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 4:
            return
        total_len = struct.unpack("!H", data[2:4])[0] or len(data)
        proto = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        src_port = dst_port = None
        if proto in (6, 17):
            src_port, dst_port = struct.unpack("!HH", data[ihl:ihl + 4])

        if src_ip == self.local_ip:
            remote_ip, remote_port, local_port, direction = dst_ip, dst_port, src_port, "送信"
        elif dst_ip == self.local_ip:
            remote_ip, remote_port, local_port, direction = src_ip, src_port, dst_port, "受信"
        else:
            return

        proto_name = PROTO_NAMES.get(proto, str(proto))
        key = (remote_ip, remote_port, proto_name)
        entry = self.stats.setdefault(key, {
            "bytes": 0, "packets": 0, "local_port": local_port,
            "direction": direction, "pid": None, "process": None, "hostname": None,
        })
        entry["bytes"] += total_len
        entry["packets"] += 1
        entry["local_port"] = local_port

    def _process_mapping_loop(self):
        if psutil is None:
            return
        while not self._stop.is_set():
            try:
                port_to_pid = {}
                for c in psutil.net_connections(kind="inet4"):
                    if c.laddr:
                        port_to_pid[c.laddr.port] = c.pid
                name_cache = {}
                for entry in self.stats.values():
                    pid = port_to_pid.get(entry.get("local_port"))
                    if pid and pid not in name_cache:
                        try:
                            name_cache[pid] = psutil.Process(pid).name()
                        except Exception:
                            name_cache[pid] = f"pid:{pid}"
                    entry["pid"] = pid
                    entry["process"] = name_cache.get(pid)
            except Exception:
                pass
            self._stop.wait(2.0)

    def resolve_hostname_async(self, ip):
        """逆引きDNSをバックグラウンドで試みる(キャッシュ済みならそれを返す、失敗はNoneのまま)。"""
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        if ip in self._resolving:
            return None
        self._resolving.add(ip)

        def worker():
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = ""
            self._hostname_cache[ip] = name
            self._resolving.discard(ip)

        threading.Thread(target=worker, daemon=True).start()
        return None

    def top_talkers(self, limit=30):
        rows = []
        for (remote_ip, remote_port, proto_name), entry in self.stats.items():
            rows.append({
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "proto": proto_name,
                "hostname": self._hostname_cache.get(remote_ip, ""),
                **entry,
            })
        rows.sort(key=lambda r: r["bytes"], reverse=True)
        return rows[:limit]


def _selftest():
    gh = pcap_global_header()
    assert len(gh) == 24, len(gh)
    magic, vmaj, vmin, tz, sig, snap, link = struct.unpack("<IHHiIII", gh)
    assert magic == PCAP_MAGIC and (vmaj, vmin) == (2, 4), (hex(magic), vmaj, vmin)
    assert link == PCAP_LINKTYPE_RAW and snap == PCAP_SNAPLEN, (link, snap)

    payload = b"\x45\x00\x00\x1c" + b"\xaa" * 24
    rec = pcap_packet_record(payload, 1_700_000_000.5)
    sec, usec, captured, orig = struct.unpack("<IIII", rec[:16])
    assert sec == 1_700_000_000 and usec == 500_000, (sec, usec)
    assert captured == orig == len(payload), (captured, orig)
    assert rec[16:] == payload

    # スナップ長を超えるパケットは切り詰められるが、元の長さは保持される
    big = b"\x00" * (PCAP_SNAPLEN + 100)
    rec_big = pcap_packet_record(big, 1.0)
    _, _, cap_big, orig_big = struct.unpack("<IIII", rec_big[:16])
    assert cap_big == PCAP_SNAPLEN and orig_big == len(big), (cap_big, orig_big)

    # 往復テスト: 実際にファイルへ書き、独立したパーサで読み戻して一致するか
    import tempfile
    packets = [
        (b"\x45\x00\x00\x28" + bytes(range(36)), 1_700_000_001.25),
        (b"\x45\x00\x00\x14" + b"\xff" * 16, 1_700_000_002.75),
    ]
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "t.pcap"
        with open(path, "wb") as f:
            f.write(pcap_global_header())
            for data, ts in packets:
                f.write(pcap_packet_record(data, ts))

        raw = path.read_bytes()
        assert struct.unpack("<I", raw[:4])[0] == PCAP_MAGIC
        pos, read_back = 24, []
        while pos < len(raw):
            sec, usec, cap, orig = struct.unpack("<IIII", raw[pos:pos + 16])
            pos += 16
            read_back.append((raw[pos:pos + cap], sec + usec / 1_000_000))
            assert cap == orig, (cap, orig)
            pos += cap
        assert read_back == packets, read_back
        assert pos == len(raw), "ファイル末尾に余分なバイトがある"

    print("traffic_monitor selftest: OK")


if __name__ == "__main__":
    _selftest()
