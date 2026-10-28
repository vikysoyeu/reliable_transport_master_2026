import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

T_START = 0
T_END = 1
T_DATA = 2
T_ACK = 3

CHUNK = 1456  # 1472 - 16 byte header
TIMEOUT = 0.5


def build(ptype, seq, payload=b""):
    h = PacketHeader(type=ptype, seq_num=seq, length=len(payload))
    h.checksum = 0
    h.checksum = compute_checksum(h / payload)
    return bytes(h / payload)


def read_ack(raw):
    # returns ack number or -1 if packet is bad
    if len(raw) < 16:
        return -1
    h = PacketHeader(raw[:16])
    if h.type != T_ACK:
        return -1
    got = h.checksum
    h.checksum = 0
    if compute_checksum(h / raw[16:16 + h.length]) != got:
        return -1
    return h.seq_num


def wait_ack(sock, limit):
    """wait for one valid ack for at most `limit` seconds, -1 if none"""
    end_time = time.time() + limit
    while True:
        left = end_time - time.time()
        if left <= 0:
            return -1
        sock.settimeout(left)
        try:
            raw, _ = sock.recvfrom(2048)
        except socket.timeout:
            return -1
        except ConnectionResetError:
            continue
        a = read_ack(raw)
        if a != -1:
            return a


def sender(receiver_ip, receiver_port, window_size):
    dest = (receiver_ip, receiver_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    data = sys.stdin.buffer.read()
    chunks = []
    pos = 0
    while pos < len(data):
        chunks.append(data[pos:pos + CHUNK])
        pos = pos + CHUNK
    total = len(chunks)

    # ---- handshake: START ----
    start_pkt = build(T_START, 0)
    while True:
        s.sendto(start_pkt, dest)
        a = wait_ack(s, TIMEOUT)
        if a == 1:
            break

    # packets are numbered 1..total, chunk i is chunks[i - 1]
    pkts = {}
    for i in range(total):
        pkts[i + 1] = build(T_DATA, i + 1, chunks[i])

    base = 1      # oldest packet not acked
    nxt = 1       # next new packet to send
    deadline = time.time() + TIMEOUT

    while base <= total:
        # fill the window
        while nxt < base + window_size and nxt <= total:
            s.sendto(pkts[nxt], dest)
            nxt += 1

        remain = deadline - time.time()
        if remain <= 0:
            # timeout -> go back and resend the whole window
            k = base
            while k < nxt:
                s.sendto(pkts[k], dest)
                k += 1
            deadline = time.time() + TIMEOUT
            continue

        a = wait_ack(s, remain)
        if a == -1:
            continue  # loop again, timeout branch will handle it
        if a > base and a <= total + 1:
            base = a
            deadline = time.time() + TIMEOUT

    # ---- close: END ----
    end_pkt = build(T_END, total + 1)
    s.sendto(end_pkt, dest)
    wait_ack(s, TIMEOUT)
    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
