import threading
import time
from datetime import datetime

from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP

from app import db

PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
    132: "SCTP",
}

IPV6_EXTENSION_HEADERS = {0, 43, 44, 60}


def parse_packet(pkt):
    if IP in pkt:
        layer = pkt[IP]
        number = layer.proto
    elif IPv6 in pkt:
        layer = pkt[IPv6]
        number = layer.nh
        payload = layer.payload
        while number in IPV6_EXTENSION_HEADERS and hasattr(payload, "nh"):
            number = payload.nh
            payload = payload.payload
    else:
        return None

    source_port = None
    destination_port = None
    if TCP in pkt:
        source_port = pkt[TCP].sport
        destination_port = pkt[TCP].dport
    elif UDP in pkt:
        source_port = pkt[UDP].sport
        destination_port = pkt[UDP].dport

    return (
        layer.src,
        layer.dst,
        PROTOCOLS.get(number, f"PROTO_{number}"),
        len(pkt),
        source_port,
        destination_port,
        datetime.fromtimestamp(float(pkt.time)),
    )


class PacketBuffer:
    def __init__(self, conn, session_id, batch_size=100, limit=0, flush_interval=2.0):
        self.conn = conn
        self.session_id = session_id
        self.batch_size = batch_size
        self.limit = limit
        self.flush_interval = flush_interval
        self.rows = []
        self.total = 0
        self.closed = False
        self.last_flush = time.time()
        self.lock = threading.Lock()

    def add(self, pkt):
        row = parse_packet(pkt)
        if row is None:
            return
        with self.lock:
            if self.closed or (self.limit and self.total >= self.limit):
                return
            self.rows.append(row)
            self.total += 1
            if len(self.rows) >= self.batch_size:
                self._flush()

    def flush_if_due(self):
        with self.lock:
            if time.time() - self.last_flush >= self.flush_interval:
                self._flush()

    def close(self):
        with self.lock:
            self.closed = True
            self._flush()

    def _flush(self):
        if self.rows:
            db.insert_packets(self.conn, self.session_id, self.rows)
            self.rows = []
        self.last_flush = time.time()


def run_capture(conn, interface, batch_size, duration, limit, stop_event):
    session_id = db.start_session(conn, interface)
    buffer = PacketBuffer(conn, session_id, batch_size, limit)
    sniffer = AsyncSniffer(iface=interface, prn=buffer.add, store=False)
    status = "completed"
    started = time.time()

    try:
        sniffer.start()
        while not stop_event.wait(0.2):
            if not sniffer.thread.is_alive():
                error = getattr(sniffer, "exception", None)
                if error:
                    raise error
                break
            if limit and buffer.total >= limit:
                break
            if duration and time.time() - started >= duration:
                break
            buffer.flush_if_due()
    except Exception:
        status = "failed"
        raise
    finally:
        try:
            buffer.close()
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass
            db.finish_session(conn, session_id, status)

    return session_id