#!/usr/bin/env python3
"""
Withings Body+ (WBS05) BLE probe over WPP (Withings Proprietary Protocol).

Собрано по открытым источникам (без весов под рукой, НЕ проверено на железе):
  - фрейминг/аутентификация:  Gadgetbridge (withingssteelhr), DavidVentura/withouthings, SureshotM6/scanwatch_ble
  - раскладка "stored measures": tools/wpp.json из withouthings (сгенерировано из Health Mate)
  - UUID сервиса Body+:          комментарий "Body+ 6e scale" в scanwatch_ble/scanwatch.py

Использование (на Пи, bleak поверх BlueZ):
  pip install bleak
  python3 withings_probe.py scan                      # найти Withings-устройства, показать UUID
  python3 withings_probe.py probe                     # PROBE → (challenge?) → GETSTATE → GETALL
  python3 withings_probe.py probe --secret <32 симв.> # если весы шлют challenge
  python3 withings_probe.py probe --secret S --delete # после удачного чтения — DELALL
  python3 withings_probe.py pair --secret S --account-id 123456   # на СБРОШЕННЫХ весах: прописать свой ключ

Весы должны рекламироваться по BLE: встань на них (режим Bluetooth) или нажми кнопку снизу (режим сопряжения).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import re
import secrets
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("pip install bleak", file=sys.stderr)
    raise

WITH_MARK = "5749-5448"  # ASCII "WITH" в UUID всех устройств Withings
BODYPLUS_SERVICE = "00000020-5749-5448-0005-000000000000"
BODYPLUS_TXRX = "00000024-5749-5448-0005-000000000000"

# --- команды (CMD_*) ---
CMD_ERROR = 256
CMD_PROBE = 257
CMD_SCALE_SESSION = 269
CMD_STORED_MEASURE = 271
CMD_DISCONNECT = 272
CMD_SETUP_OK = 275
CMD_SYNC_OK = 277
CMD_TIME_SET = 1281
CMD_PROBE_CHALLENGE = 296
CMD_ASSOCIATION_KEYS_SET = 308
CMD_SYNC_REQUEST = 321
SLAVE_REQ = 0x4000

# --- типы TLV (TYPE_*) ---
T_NULL = 256
T_PROBE_REPLY = 257
T_CMDERROR = 272
T_STORED_ACTION = 276
T_STORED_STATUS = 277
T_STORED_META = 278
T_STORED_DATA = 279
T_PROBE_CHALLENGE = 290
T_PROBE_CHALLENGE_RESPONSE = 291
T_APP_PROBE = 298
T_STORED_META_EXTEND = 299
T_FACTORY_STATE = 300
T_ACCOUNT_KEY = 309
T_ADV_KEY = 310
T_TIME_SET = 1281
T_BATTERY_STATUS = 1284
T_APP_PROBE_OS_VERSION = 2344
T_STORED_DATA_EXTEND_POS = 2451

STORED_GETSTATE, STORED_GETALL, STORED_DELALL = 0, 1, 2

TYPE_NAMES = {
    T_NULL: "Null", T_PROBE_REPLY: "ProbeReply", T_CMDERROR: "Cmderror",
    T_STORED_ACTION: "StoredMeasureAction", T_STORED_STATUS: "StoredMeasureStatus",
    T_STORED_META: "StoredMeasureMeta", T_STORED_DATA: "StoredMeasureData",
    T_PROBE_CHALLENGE: "ProbeChallenge", T_PROBE_CHALLENGE_RESPONSE: "ProbeChallengeResponse",
    T_APP_PROBE: "AppProbe", T_STORED_META_EXTEND: "StoredMeasureMetaExtend",
    T_FACTORY_STATE: "FactoryState", T_ACCOUNT_KEY: "AccountKey", T_ADV_KEY: "AdvKey",
    T_TIME_SET: "TimeSet", T_BATTERY_STATUS: "BatteryStatus",
    T_STORED_DATA_EXTEND_POS: "StoredMeasureDataExtendPos",
}
CMD_NAMES = {
    CMD_ERROR: "CMD_ERROR", CMD_PROBE: "CMD_PROBE", CMD_SCALE_SESSION: "CMD_SCALE_SESSION",
    CMD_STORED_MEASURE: "CMD_STORED_MEASURE", CMD_DISCONNECT: "CMD_DISCONNECT",
    CMD_SETUP_OK: "CMD_SETUP_OK", CMD_SYNC_OK: "CMD_SYNC_OK", CMD_TIME_SET: "CMD_TIME_SET",
    CMD_PROBE_CHALLENGE: "CMD_PROBE_CHALLENGE", CMD_ASSOCIATION_KEYS_SET: "CMD_ASSOCIATION_KEYS_SET",
    CMD_SYNC_REQUEST: "CMD_SYNC_REQUEST",
}
# Типы замеров — те же, что в публичном Withings API (measure.type)
MEAS_TYPES = {
    1: ("weight", "kg"), 4: ("height", "m"), 5: ("fat_free_mass", "kg"), 6: ("fat_ratio", "%"),
    8: ("fat_mass", "kg"), 9: ("diastolic", "mmHg"), 10: ("systolic", "mmHg"), 11: ("heart_rate", "bpm"),
    12: ("temperature", "C"), 71: ("body_temperature", "C"), 73: ("skin_temperature", "C"),
    76: ("muscle_mass", "kg"), 77: ("hydration", "kg"), 88: ("bone_mass", "kg"),
    91: ("pulse_wave_velocity", "m/s"), 155: ("vascular_age", "y"),
}


# ---------------------------------------------------------------- wire helpers
def wstr(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


def wbytes(b: bytes) -> bytes:
    return bytes([len(b)]) + b


def tlv(t: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HH", t, len(payload)) + payload


def frame(cmd: int, *tlvs: bytes) -> bytes:
    body = b"".join(tlvs)
    return b"\x01" + struct.pack(">HH", cmd, len(body)) + body


class Reader:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def left(self) -> int:
        return len(self.b) - self.i

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise ValueError("short read")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def u8(self): return self.take(1)[0]
    def i8(self): return struct.unpack(">b", self.take(1))[0]
    def u16(self): return struct.unpack(">H", self.take(2))[0]
    def i16(self): return struct.unpack(">h", self.take(2))[0]
    def u32(self): return struct.unpack(">I", self.take(4))[0]
    def i32(self): return struct.unpack(">i", self.take(4))[0]
    def s(self): return self.take(self.u8()).decode(errors="replace")
    def by(self): return self.take(self.u8())


def parse_tlvs(payload: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i + 4 <= len(payload):
        t, ln = struct.unpack(">HH", payload[i:i + 4])
        out.append((t, payload[i + 4:i + 4 + ln]))
        i += 4 + ln
    if i != len(payload):
        print(f"  !! trailing bytes: {payload[i:].hex()}")
    return out


def decode(t: int, v: bytes):
    r = Reader(v)
    try:
        if t == T_NULL:
            return {}
        if t == T_PROBE_REPLY:
            return dict(vid=r.u16(), pid=r.u16(), name=r.s(), mac=r.s(), secret=r.s(),
                        hardVersion=r.u32(), mfgId=r.s(), blVersion=r.u32(),
                        softVersion=r.u32(), rescueVersion=r.u32())
        if t == T_PROBE_CHALLENGE:
            return dict(mac=r.s(), challenge=r.by().hex())
        if t == T_PROBE_CHALLENGE_RESPONSE:
            return dict(answer=r.by().hex())
        if t == T_FACTORY_STATE:
            return dict(value=r.u8())
        if t == T_CMDERROR:
            return dict(cmd=r.u16(), err=r.i32())
        if t == T_STORED_ACTION:
            return dict(cmd=r.u8(), rc=r.i8())
        if t == T_STORED_STATUS:
            return dict(cnt=r.i16(), oldestMeasTime=ts(r.i32()), wifiConfigured=r.i8())
        if t == T_STORED_META:
            uid = r.u32()
            cnt = r.u8()
            # data_size=23 в Health Mate => массив идёт со своим байтом длины (макс. 3 id)
            if r.left() >= 1 + 4 * cnt + 5 or cnt == 0:
                n = r.u8()
                ids = [r.u32() for _ in range(n)]
            else:
                ids = [r.u32() for _ in range(cnt)]
            return dict(uid=uid, userIdCnt=cnt, userId=ids, attrib=r.u8(), time=ts(r.u32()))
        if t == T_STORED_DATA:
            value, mtype, exp = r.i32(), r.u16(), r.i16()
            name, unit = MEAS_TYPES.get(mtype, (f"type{mtype}", "?"))
            return dict(type=mtype, name=name, value=value * (10 ** exp), unit=unit, raw=value, exponent=exp)
        if t == T_STORED_META_EXTEND:
            return dict(algo=r.u8())
        if t == T_STORED_DATA_EXTEND_POS:
            return dict(position=r.u8())
        if t == T_BATTERY_STATUS:
            return dict(percent=r.u8(), state=r.u8(), mv=r.u32())
    except Exception as e:  # noqa: BLE001
        return dict(_decode_error=str(e), raw=v.hex())
    return dict(raw=v.hex())


def ts(x: int) -> str:
    try:
        return f"{x} ({datetime.fromtimestamp(x, tz=timezone.utc).isoformat()})"
    except Exception:  # noqa: BLE001
        return str(x)


def dump_frame(direction: str, raw: bytes):
    cmd_raw, ln = struct.unpack(">HH", raw[1:5])
    cmd = cmd_raw & 0x3FFF
    slave = bool(cmd_raw & SLAVE_REQ)
    print(f"{direction} {CMD_NAMES.get(cmd, cmd)}{' [SLAVE_REQ]' if slave else ''} len={ln}  hex={raw.hex()}")
    for t, v in parse_tlvs(raw[5:5 + ln]):
        print(f"    {TYPE_NAMES.get(t, t)}({t}) {decode(t, v)}")


# ---------------------------------------------------------------- BLE link
class Link:
    def __init__(self, client: BleakClient, char):
        self.client, self.char = client, char
        self.buf = bytearray()
        self.q: asyncio.Queue[bytes] = asyncio.Queue()

    def on_notify(self, _, data: bytearray):
        self.buf.extend(data)
        while len(self.buf) >= 5:
            if self.buf[0] != 0x01:
                print(f"  !! unexpected leading byte, dropping: {bytes(self.buf).hex()}")
                self.buf.clear()
                return
            ln = struct.unpack(">H", self.buf[3:5])[0]
            if len(self.buf) < 5 + ln:
                return
            fr = bytes(self.buf[:5 + ln])
            del self.buf[:5 + ln]
            dump_frame("<--", fr)
            self.q.put_nowait(fr)

    async def send(self, raw: bytes):
        dump_frame("-->", raw)
        chunk = max(20, (self.client.mtu_size or 23) - 3)
        for i in range(0, len(raw), chunk):
            await self.client.write_gatt_char(self.char, raw[i:i + chunk], response=True)

    async def transact(self, raw: bytes, idle: float = 2.0, first: float = 8.0) -> list[bytes]:
        """Отправить и собрать все ответные фреймы: до Null-TLV или до тишины `idle` сек."""
        await self.send(raw)
        frames = []
        timeout = first
        while True:
            try:
                fr = await asyncio.wait_for(self.q.get(), timeout)
            except asyncio.TimeoutError:
                break
            cmd_raw = struct.unpack(">H", fr[1:3])[0]
            if cmd_raw & SLAVE_REQ:
                continue  # инициатива устройства, для зонда игнорируем
            frames.append(fr)
            if (cmd_raw & 0x3FFF) == CMD_ERROR:
                break
            if any(t == T_NULL for t, _ in parse_tlvs(fr[5:])):
                break
            timeout = idle
        return frames


def tlvs_of(frames: list[bytes]) -> list[tuple[int, bytes]]:
    out = []
    for fr in frames:
        out += parse_tlvs(fr[5:])
    return out


def sha1_answer(challenge: bytes, mac: str, secret: str) -> bytes:
    return hashlib.sha1(challenge + mac.encode() + secret.encode()).digest()


# ---------------------------------------------------------------- actions
async def do_scan(timeout: float):
    print(f"scanning {timeout:.0f}s — встань на весы или нажми кнопку снизу…")
    seen = {}

    def cb(dev, adv):
        uuids = [u.lower() for u in (adv.service_uuids or [])]
        if any(WITH_MARK in u for u in uuids) or (adv.local_name or "").lower().startswith(("body", "withings", "wbs")):
            key = dev.address
            if key not in seen:
                seen[key] = True
                print(f"  {dev.address}  rssi={adv.rssi}  name={adv.local_name!r}  services={uuids}  mfg={ {k: v.hex() for k, v in (adv.manufacturer_data or {}).items()} }")

    async with BleakScanner(detection_callback=cb):
        await asyncio.sleep(timeout)
    if not seen:
        print("ничего похожего на Withings не найдено")


async def find_device(address: str | None, timeout: float):
    if address:
        dev = await BleakScanner.find_device_by_address(address, timeout=timeout)
    else:
        def flt(dev, adv):
            uuids = [u.lower() for u in (adv.service_uuids or [])]
            return any(WITH_MARK in u for u in uuids)
        print(f"ищу устройство Withings до {timeout:.0f}s — встань на весы…")
        dev = await BleakScanner.find_device_by_filter(flt, timeout=timeout)
    if dev is None:
        sys.exit("устройство не найдено")
    return dev


async def open_link(dev) -> tuple[BleakClient, Link]:
    client = BleakClient(dev, timeout=45)
    await client.connect()
    print(f"connected {dev.address}, mtu={client.mtu_size}")
    # Connection Update сразу после соединения: весы медленные, дефолтные 420 мс supervision их роняют
    try:
        con = subprocess.run(["sudo", "hcitool", "con"], capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"handle (\d+)", con)
        if m:
            r = subprocess.run(["sudo", "hcitool", "lecup", "--handle", m.group(1), "--min", "24", "--max", "40",
                                "--latency", "0", "--timeout", "500"], capture_output=True, text=True, timeout=3)
            print(f"lecup handle {m.group(1)}: rc={r.returncode} {r.stdout.strip()} {r.stderr.strip()}")
        else:
            print("lecup: handle not found in hcitool con:", con.strip())
    except Exception as e:  # noqa: BLE001
        print("lecup failed:", e)
    svc = None
    for s in client.services:
        print(f"  service {s.uuid}")
        for c in s.characteristics:
            print(f"      char {c.uuid} {c.properties}")
        if WITH_MARK in s.uuid.lower():
            svc = s
    if svc is None:
        await client.disconnect()
        sys.exit("нет сервиса с 5749-5448 (WITH)")
    cands = [c for c in svc.characteristics
             if ("notify" in c.properties or "indicate" in c.properties)
             and ("write" in c.properties or "write-without-response" in c.properties)]
    cands.sort(key=lambda c: (not c.uuid.lower().startswith("00000024"), not c.uuid.lower().startswith("00000023")))
    if not cands:
        await client.disconnect()
        sys.exit("нет характеристики notify+write в сервисе Withings")
    char = cands[0]
    print(f"using TX/RX char {char.uuid}")
    link = Link(client, char)
    await client.start_notify(char, link.on_notify)
    return client, link


async def probe_and_auth(link: Link, secret: str | None) -> dict:
    """CMD_PROBE → либо ProbeReply, либо challenge (тогда нужен secret). Возвращает ProbeReply."""
    probe = frame(CMD_PROBE,
                  tlv(T_APP_PROBE, struct.pack(">BBI", 1, 1, 7050201)),   # os=Android, app=HealthMate, version
                  tlv(T_APP_PROBE_OS_VERSION, struct.pack(">H", 35)))
    frames = await link.transact(probe)
    if not frames:
        sys.exit("нет ответа на PROBE")
    cmd = struct.unpack(">H", frames[0][1:3])[0] & 0x3FFF
    tl = dict(tlvs_of(frames))
    if cmd == CMD_PROBE and T_PROBE_REPLY in tl:
        print("== challenge НЕ потребовался")
        return decode(T_PROBE_REPLY, tl[T_PROBE_REPLY])
    if cmd == CMD_PROBE_CHALLENGE and T_PROBE_CHALLENGE in tl:
        ch = decode(T_PROBE_CHALLENGE, tl[T_PROBE_CHALLENGE])
        mac, challenge = ch["mac"], bytes.fromhex(ch["challenge"])
        if not secret:
            sys.exit(f"весы требуют challenge: mac={mac} challenge={ch['challenge']}\n"
                     "нужен klSecret (из облака Withings: scalews.withings.com/cgi-bin/association) "
                     "или сброс весов + `pair --secret ...`")
        ours = secrets.token_bytes(16)
        reply = frame(CMD_PROBE_CHALLENGE,
                      tlv(T_PROBE_CHALLENGE_RESPONSE, wbytes(sha1_answer(challenge, mac, secret))),
                      tlv(T_PROBE_CHALLENGE, wstr(mac) + wbytes(ours)))
        frames = await link.transact(reply)
        tl = dict(tlvs_of(frames))
        if T_PROBE_REPLY not in tl:
            sys.exit("после challenge не пришёл ProbeReply — секрет неверный?")
        if T_PROBE_CHALLENGE_RESPONSE in tl:
            theirs = bytes.fromhex(decode(T_PROBE_CHALLENGE_RESPONSE, tl[T_PROBE_CHALLENGE_RESPONSE])["answer"])
            print("== устройство ответило на НАШ challenge:", "OK" if theirs == sha1_answer(ours, mac, secret) else "НЕ СОВПАЛО")
        return decode(T_PROBE_REPLY, tl[T_PROBE_REPLY])
    sys.exit(f"неожиданный ответ на PROBE: cmd={cmd}")


async def stored(link: Link, action: int) -> list[bytes]:
    return await link.transact(frame(CMD_STORED_MEASURE, tlv(T_STORED_ACTION, struct.pack(">Bb", action, 0))), idle=3.0)


def print_measurements(frames: list[bytes]):
    groups, cur = [], None
    for t, v in tlvs_of(frames):
        if t == T_STORED_META:
            cur = {"meta": decode(t, v), "data": []}
            groups.append(cur)
        elif t == T_STORED_DATA and cur is not None:
            cur["data"].append(decode(t, v))
    print(f"\n== замеров: {len(groups)}")
    for g in groups:
        m = g["meta"]
        vals = ", ".join(f"{d['name']}={d['value']:g}{d['unit']}" for d in g["data"])
        print(f"  {m['time']}  users={m['userId']} attrib={m['attrib']}  {vals}")


async def do_probe(args):
    dev = await find_device(args.address, args.timeout)
    client, link = await open_link(dev)
    try:
        reply = await probe_and_auth(link, args.secret)
        print("== ProbeReply:", reply)
        st = await stored(link, STORED_GETSTATE)
        tl = dict(tlvs_of(st))
        if T_STORED_STATUS in tl:
            print("== StoredMeasureStatus:", decode(T_STORED_STATUS, tl[T_STORED_STATUS]))
        allf = await stored(link, STORED_GETALL)
        print_measurements(allf)
        if args.delete:
            await stored(link, STORED_DELALL)
            print("== DELALL sent")
        await link.transact(frame(CMD_DISCONNECT), first=2.0, idle=0.5)
    finally:
        await client.disconnect()


async def do_pair(args):
    if len(args.secret) != 32 or not args.secret.isascii():
        sys.exit("secret должен быть 32 ASCII-символа")
    dev = await find_device(args.address, args.timeout)
    client, link = await open_link(dev)
    try:
        reply = await probe_and_auth(link, None)  # на сброшенных весах challenge быть не должно
        print("== ProbeReply:", reply)
        fr = frame(CMD_ASSOCIATION_KEYS_SET,
                   tlv(T_ACCOUNT_KEY, struct.pack(">I", args.account_id) + wstr(args.secret)),
                   tlv(T_ADV_KEY, wstr(args.secret)))
        await link.transact(fr)
        await link.transact(frame(CMD_SETUP_OK))
        now = int(time.time())
        await link.transact(frame(CMD_TIME_SET, tlv(T_TIME_SET, struct.pack(">IiIi", now, 0, 0, 0))))
        print("== ключи записаны; дальше `probe --secret <тот же secret>`")
        await link.transact(frame(CMD_DISCONNECT), first=2.0, idle=0.5)
    finally:
        await client.disconnect()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("--timeout", type=float, default=30)
    for name in ("probe", "pair"):
        q = sub.add_parser(name)
        q.add_argument("--address")
        q.add_argument("--timeout", type=float, default=60)
        q.add_argument("--secret")
        if name == "probe":
            q.add_argument("--delete", action="store_true", help="после чтения стереть замеры на весах")
        else:
            q.add_argument("--account-id", type=int, default=123456)
    args = p.parse_args()
    if args.cmd == "scan":
        asyncio.run(do_scan(args.timeout))
    elif args.cmd == "probe":
        asyncio.run(do_probe(args))
    else:
        asyncio.run(do_pair(args))


if __name__ == "__main__":
    main()
