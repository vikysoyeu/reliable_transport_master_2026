import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

T_START = 0
T_END = 1
T_DATA = 2
T_ACK = 3


def make_ack(seq):
    h = PacketHeader(type=T_ACK, seq_num=seq, length=0)
    h.checksum = 0
    h.checksum = compute_checksum(h / b"")
    return bytes(h / b"")


def parse(raw):
    """return (type, seq, payload) or None when packet is broken"""
    if len(raw) < 16:
        return None
    h = PacketHeader(raw[:16])
    body = raw[16:16 + h.length]
    if len(body) != h.length:
        return None
    given = h.checksum
    h.checksum = 0
    if compute_checksum(h / body) != given:
        return None
    return h.type, h.seq_num, body


def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))
    out = sys.stdout.buffer

    connected = False
    expected = 1
    held = {}

    while True:
        try:
            raw, addr = s.recvfrom(2048)
        except ConnectionResetError:
            continue

        res = parse(raw)
        if res is None:
            continue
        ptype, seq, body = res

        if ptype == T_START:
            if not connected:
                connected = True
                expected = 1
                held = {}
                s.sendto(make_ack(1), addr)
            continue

        if not connected:
            continue

        if ptype == T_DATA:
            if seq >= expected + window_size:
                continue  # too far ahead, drop without ack
            if seq >= expected and seq not in held:
                held[seq] = body
            # ack exactly this packet (not cumulative). Old packets are acked
            # again too, otherwise the sender could wait forever.
            s.sendto(make_ack(seq), addr)
            while expected in held:
                out.write(held.pop(expected))
                expected += 1
            out.flush()

        elif ptype == T_END:
            s.sendto(make_ack(seq + 1), addr)
            out.flush()
            break

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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
