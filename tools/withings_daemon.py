#!/usr/bin/env python3
"""
Демон для Withings Body+: слушает эфир, при СВЕЖЕЙ рекламе весов подключается (сканер продолжает
работать — bleak #631), ведёт сессию как Health Mate и складывает замеры в JSONL.

Сессия: settle 2 с → notify → PROBE → CONNECT_REASON → STORED GETSTATE → [GETALL → save → DELALL]
        → [WIFI_GET_SETTINGS, WIFI_SETTINGS enable=0, GETSTATE] → SYNC_OK → [SETUP_OK] → DISCONNECT

  python3 withings_daemon.py --address 00:24:E4:xx:xx:xx --out measurements.jsonl --delete [--disable-wifi] [--setup-ok]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
import time
from datetime import datetime, timezone

from bleak import BleakClient, BleakScanner

import withings_probe as wp

CMD_WIFI_GET_SETTINGS = 260
CMD_WIFI_SETTINGS = 265
CMD_CONNECT_REASON = 273
CMD_SYNC_OK = 277
CMD_COMM_SUPPORT = 281
T_CONNECT_REASON = 280
T_WIFI_ENABLE = 270
REASONS = {0: "UNKNOWN", 1: "USER_REQ", 2: "DEVICE_REQ", 3: "FIRM_UPDATE", 4: "READY_TO_UPDATE",
           5: "RESCUE_FW", 6: "TRAINING", 7: "EVENT", 8: "BAT_LVL_INFO", 9: "WUP_SYNC_REQ", 10: "FEATURE_TAGS_SYNC"}


def log(*a):
    print(datetime.now().strftime("%H:%M:%S"), *a, flush=True)


async def session(dev, out_path: str, delete: bool, secret: str | None,
                  disable_wifi: bool, setup_ok: bool) -> int:
    client = BleakClient(dev, timeout=40, disconnected_callback=lambda c: log("disconnected by peer"))
    await client.connect()
    log(f"connected, mtu={client.mtu_size}")
    n = 0
    try:
        await asyncio.sleep(2.0)  # Gadgetbridge: дать устройству «устаканиться» перед первой GATT-операцией
        svc = next((s for s in client.services if wp.WITH_MARK in s.uuid.lower()), None)
        if svc is None:
            raise RuntimeError("no Withings service")
        chars = [c for c in svc.characteristics if "notify" in c.properties and
                 ("write" in c.properties or "write-without-response" in c.properties)]
        chars.sort(key=lambda c: not c.uuid.lower().startswith("00000024"))
        link = wp.Link(client, chars[0])
        await client.start_notify(chars[0], link.on_notify)

        reply = await wp.probe_and_auth(link, secret)
        log("ProbeReply:", reply.get("name"), "fw", reply.get("softVersion"), "mac", reply.get("mac"))

        # RTC весов сбрасывается при смене батареек → выставляем время в каждой сессии (Health Mate делает так же)
        now = int(time.time())
        gmt_off = -time.timezone if not time.daylight else -time.altzone
        fr = await link.transact(wp.frame(wp.CMD_TIME_SET, wp.tlv(wp.T_TIME_SET, struct.pack(">IiIi", now, gmt_off, 0, gmt_off))),
                                 first=6.0, idle=1.0)
        log("TIME_SET →", [(t, v.hex()) for t, v in wp.tlvs_of(fr)] or "echo/none")

        fr = await link.transact(wp.frame(CMD_CONNECT_REASON), first=6.0, idle=1.0)
        tl = dict(wp.tlvs_of(fr))
        if T_CONNECT_REASON in tl and len(tl[T_CONNECT_REASON]) >= 2:
            r = struct.unpack(">H", tl[T_CONNECT_REASON][:2])[0]
            log(f"ConnectReason: {r} ({REASONS.get(r, '?')})")
        else:
            log("ConnectReason: no answer", {t: v.hex() for t, v in tl.items()})

        st = dict(wp.tlvs_of(await wp.stored(link, wp.STORED_GETSTATE)))
        status = wp.decode(wp.T_STORED_STATUS, st[wp.T_STORED_STATUS]) if wp.T_STORED_STATUS in st else {}
        log("StoredMeasureStatus:", status)

        if status.get("cnt", 0) > 0:
            frames = await wp.stored(link, wp.STORED_GETALL)
            groups, cur = [], None
            for t, v in wp.tlvs_of(frames):
                if t == wp.T_STORED_META:
                    cur = {"meta": wp.decode(t, v), "data": []}
                    groups.append(cur)
                elif t == wp.T_STORED_DATA and cur is not None:
                    cur["data"].append(wp.decode(t, v))
            with open(out_path, "a") as f:
                for g in groups:
                    f.write(json.dumps({
                        "received_at": datetime.now(timezone.utc).isoformat(),
                        "device_mac": dev.address,
                        "meta": g["meta"],
                        "values": {d["name"]: d["value"] for d in g["data"]},
                        "raw": g["data"],
                    }, ensure_ascii=False) + "\n")
            n = len(groups)
            log(f"saved {n} measurement(s) to {out_path}")
            for g in groups:
                log("  ", g["meta"].get("time"), {d["name"]: d["value"] for d in g["data"]})
            if delete and n > 0:
                await wp.stored(link, wp.STORED_DELALL)
                log("DELALL sent")

        if disable_wifi and status.get("wifiConfigured", 0):
            fr = await link.transact(wp.frame(CMD_WIFI_GET_SETTINGS), first=6.0, idle=1.5)
            log("WIFI_GET_SETTINGS:", [(t, v.hex()) for t, v in wp.tlvs_of(fr)])
            fr = await link.transact(wp.frame(CMD_WIFI_SETTINGS, wp.tlv(T_WIFI_ENABLE, struct.pack(">b", 0))),
                                     first=8.0, idle=1.5)
            log("WIFI_SETTINGS enable=0 →", [(t, v.hex()) for t, v in wp.tlvs_of(fr)] or "no reply")
            st2 = dict(wp.tlvs_of(await wp.stored(link, wp.STORED_GETSTATE)))
            if wp.T_STORED_STATUS in st2:
                log("StoredMeasureStatus after:", wp.decode(wp.T_STORED_STATUS, st2[wp.T_STORED_STATUS]))

        fr = await link.transact(wp.frame(CMD_SYNC_OK), first=6.0, idle=1.0)
        log("SYNC_OK →", len(fr), "frame(s)")
        if setup_ok:
            fr = await link.transact(wp.frame(wp.CMD_SETUP_OK), first=6.0, idle=1.0)
            log("SETUP_OK →", len(fr), "frame(s)")
        fr = await link.transact(wp.frame(wp.CMD_DISCONNECT), first=3.0, idle=0.5)
        log("DISCONNECT →", len(fr), "frame(s)")
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    return n


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--address", required=True)
    p.add_argument("--out", default="measurements.jsonl")
    p.add_argument("--delete", action="store_true")
    p.add_argument("--secret")
    p.add_argument("--disable-wifi", action="store_true")
    p.add_argument("--setup-ok", action="store_true")
    p.add_argument("--upload-args", default="", help="аргументы для withings_upload.py, напр. '--userid 12345678 --mac 00:24:e4:xx:xx:xx'")
    args = p.parse_args()
    mac = args.address.upper()
    log("daemon start, waiting for", mac)

    queue: asyncio.Queue = asyncio.Queue()
    last_seen = {"t": 0.0}

    def on_adv(dev, adv):
        if dev.address.upper() != mac:
            return
        now = time.monotonic()
        if now - last_seen["t"] > 3.0:  # не спамить: одна заявка на серию реклам
            queue.put_nowait((dev, adv.rssi, now))
        last_seen["t"] = now

    def upload():
        """Отправить новые замеры в облако Withings (withings_upload.py); тихо переживает отсутствие интернета."""
        if not args.upload_args:
            return
        import subprocess, sys as _sys
        cmd = [_sys.executable, "-u", "withings_upload.py", "--in", args.out] + args.upload_args.split()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            for line in (r.stdout + r.stderr).strip().splitlines():
                log("[upload]", line)
        except Exception as e:  # noqa: BLE001
            log("[upload] failed:", repr(e))

    scanner = BleakScanner(detection_callback=on_adv)
    await scanner.start()  # сканер работает ВСЁ время, в т.ч. во время соединения (bleak #631)
    busy_until = 0.0
    next_upload = time.monotonic() + 60
    while True:
        try:
            dev, rssi, seen_at = await asyncio.wait_for(queue.get(), timeout=30)
        except asyncio.TimeoutError:
            if time.monotonic() >= next_upload:  # периодический сброс в облако (интернет может появляться эпизодически)
                upload()
                next_upload = time.monotonic() + 600
            continue
        if time.monotonic() < busy_until:
            continue
        age = time.monotonic() - seen_at
        if age > 1.5:
            log(f"stale advert ({age:.1f}s), skip")
            continue
        log(f"scale in the air rssi={rssi}, connecting")
        for attempt in range(1, 4):
            # контроллер фильтрует дубликаты рекламы, поэтому при работающем сканере ядро ждёт
            # «следующую» рекламу, которой не будет → сканер стопим и сразу создаём соединение
            await scanner.stop()
            try:
                n = await session(dev, args.out, args.delete, args.secret, args.disable_wifi, args.setup_ok)
                log(f"session done, {n} new measurement(s)")
                if n > 0:
                    upload()
                    next_upload = time.monotonic() + 600
                break
            except Exception as e:  # noqa: BLE001
                log(f"attempt {attempt} failed: {e!r}")
            finally:
                while not queue.empty():
                    queue.get_nowait()
                await scanner.start()
            await asyncio.sleep(3)  # весы после обрыва уходят в lowpower; дать им проснуться
            try:
                dev, rssi, seen_at = await asyncio.wait_for(queue.get(), 30)
                log(f"fresh advert rssi={rssi}, retrying")
            except asyncio.TimeoutError:
                log("scale gone from the air")
                break
        busy_until = time.monotonic() + 15
        while not queue.empty():
            queue.get_nowait()


if __name__ == "__main__":
    asyncio.run(main())
