#!/usr/bin/env python3
"""Через MGMT-сокет BlueZ (нужен root): удалить устройство из ядра (сбросить stale conn params)
и загрузить для него свои параметры соединения. Bind делается через ctypes, потому что python
не умеет sockaddr_hci с каналом управления."""
import ctypes
import socket
import struct
import sys

MAC = sys.argv[1] if len(sys.argv) > 1 else "00:24:E4:xx:xx:xx"
ADDR_TYPE = 1  # MGMT: 1 = LE public
MIN_INT, MAX_INT, LATENCY, TIMEOUT = 24, 40, 0, 500   # 1.25ms units / 10ms units

AF_BLUETOOTH, BTPROTO_HCI, HCI_CHANNEL_CONTROL = 31, 1, 3
libc = ctypes.CDLL(None, use_errno=True)
s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
sa = struct.pack("<HHH", AF_BLUETOOTH, 0xFFFF, HCI_CHANNEL_CONTROL)
if libc.bind(s.fileno(), sa, len(sa)) != 0:
    sys.exit(f"bind failed errno={ctypes.get_errno()}")
s.settimeout(3)


def mgmt(opcode: int, param: bytes, index: int = 0) -> None:
    s.send(struct.pack("<HHH", opcode, index, len(param)) + param)
    while True:
        r = s.recv(1024)
        ev, idx, ln = struct.unpack("<HHH", r[:6])
        body = r[6:6 + ln]
        if ev in (0x0001, 0x0002) and struct.unpack("<H", body[:2])[0] == opcode:  # complete/status for our opcode
            status = body[2]
            print(f"op 0x{opcode:04x}: {'complete' if ev == 1 else 'status'} status=0x{status:02x} {body[3:].hex()}")
            return


addr = bytes(int(x, 16) for x in reversed(MAC.split(":")))
print("remove device")
mgmt(0x0034, addr + struct.pack("<B", ADDR_TYPE))
print("load conn params")
mgmt(0x0035, struct.pack("<H", 1) + addr + struct.pack("<BHHHH", ADDR_TYPE, MIN_INT, MAX_INT, LATENCY, TIMEOUT))
