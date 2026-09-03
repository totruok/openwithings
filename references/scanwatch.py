#!/usr/bin/env python3

from datetime import datetime
from enum import Enum
import hashlib
import random
import secrets
import sys
import asyncio
from pydantic import BaseModel
import logging
import fw_parser

from bleak import BleakClient
# from bleak_winrt.windows.devices.enumeration import DevicePairingProtectionLevel


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)-15s %(name)-8s %(levelname)s: %(message)s",
)

import asyncio
import sys
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Annotated

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from wpp import (
    CmdBatteryPercent,
    CmdBatteryStatus,
    CmdDebugDump,
    CmdDebugDumpAck,
    CmdDebugSet,
    CmdDisconnect,
    CmdError,
    CmdProbe,
    CmdProbeChallenge,
    CmdSpiFlash,
    CmdSwimStatus,
    CmdTrackerUserGet,
    DebugDumpAnchor,
    DebugDumpMask,
    DebugMask,
    ProbeChallenge,
    SpiFlashCmd,
    SwimStatus,
    WppCmd,
)



# populate from https://scalews.withings.com/cgi-bin/association
KL_SECRET = MUST FILL IN SECRET STRING!

# scanwatch
# WATCH_SERVICE_UUID = "00000020-5749-5448-005d-000000000000"
# WATCH_TX_RX_UUID = "00000023-5749-5448-005d-000000000000"

# scanwatch 2
WATCH_SERVICE_UUID = "00000020-5749-5448-005e-000000000000"
WATCH_TX_RX_UUID = "00000023-5749-5448-005e-000000000000"

# Body+ 6e scale
# WATCH_SERVICE_UUID = "00000020-5749-5448-0005-000000000000"
# WATCH_TX_RX_UUID = "00000024-5749-5448-0005-000000000000"


async def watch_service():
    def match_watch_uuid(device: BLEDevice, adv: AdvertisementData):
        # TODO: also check MAC for Withings?
        if WATCH_SERVICE_UUID.lower() in adv.service_uuids:
            return True

        return False

    device: Optional[BLEDevice] = await BleakScanner.find_device_by_filter(
        match_watch_uuid, timeout=30
    )

    if device is None:
        print("no matching device found, you may need to edit WATCH_SERVICE_UUID")
        sys.exit(1)

    def handle_disconnect(client: BleakClient):
        print("Device was disconnected, goodbye.")
        # cancelling all tasks effectively ends the program
        for task in asyncio.all_tasks():
            task.cancel()

        # client.unpair()

    async with BleakClient(device, disconnected_callback=handle_disconnect, services=(WATCH_SERVICE_UUID,)) as client:
        print(f"Connected to {client.address}")

        # enumerate for debug
        # for service in client.services:
        #     logger.info("[Service] %s", service)

        #     for char in service.characteristics:
        #         if "read" in char.properties:
        #             try:
        #                 value = await client.read_gatt_char(char.uuid)
        #                 logger.info(
        #                     "  [Characteristic] %s (%s), Value: %r",
        #                     char,
        #                     ",".join(char.properties),
        #                     value,
        #                 )
        #             except Exception as e:
        #                 logger.error(
        #                     "  [Characteristic] %s (%s), Error: %s",
        #                     char,
        #                     ",".join(char.properties),
        #                     e,
        #                 )

        #         else:
        #             logger.info(
        #                 "  [Characteristic] %s (%s)", char, ",".join(char.properties)
        #             )

        #         for descriptor in char.descriptors:
        #             try:
        #                 value = await client.read_gatt_descriptor(descriptor.handle)
        #                 logger.info("    [Descriptor] %s, Value: %r", descriptor, value)
        #             except Exception as e:
        #                 logger.error("    [Descriptor] %s, Error: %s", descriptor, e)

        # await client.pair(protection_level=int(DevicePairingProtectionLevel.ENCRYPTION_AND_AUTHENTICATION))

        # loop = asyncio.get_running_loop()
        service = client.services.get_service(WATCH_SERVICE_UUID)
        tx_rx_char: BleakGATTCharacteristic = service.get_characteristic(
            WATCH_TX_RX_UUID
        )

        print(f"service: {service} char: {tx_rx_char}")

        rxq: asyncio.Queue[WppCmd] = asyncio.Queue()
        rx_buf = bytearray()

        async def do_read(_: BleakGATTCharacteristic, data: bytearray):
            nonlocal rx_buf

            rx_buf.extend(data)

            try:
                cmd_id, l, slave_req = WppCmd.decode_header(rx_buf)
                if len(rx_buf) < l:
                    return

                if slave_req:
                    print(f"###### RX {l:3d} bytes: ignoring SLAVE_REQ | {cmd_id}: {rx_buf[:l].hex()}")
                    rx_buf = rx_buf[l:]
                    return

                cmd = WppCmd.deserialize(bytes(rx_buf[:l]))
                print(f"###### RX {l:3d} bytes: {repr(cmd)}")
                rx_buf = rx_buf[l:]
            except:
                logger.exception(
                    "failed to unpack %d bytes: %s", len(rx_buf), rx_buf.hex()
                )
                await client.disconnect()
                return

            await rxq.put(cmd)

        await client.start_notify(tx_rx_char, do_read)

        # cmds are always:
        # 01
        # 0x#### id (be)
        # 0x#### len (be)
        # ...
        #
        # some commands have Null arguments (0100_0000)

        async def transact(cmd: WppCmd) -> WppCmd:
            data = cmd.serialize()
            print(f"###### TX {len(data):3d} bytes: {repr(cmd)}")
            await client.write_gatt_char(tx_rx_char, data, response=True)
            rsp = await rxq.get()
            if isinstance(rsp, CmdError):
                raise Exception(rsp)

            return rsp

        async def transact_until_null(cmd: WppCmd) -> WppCmd:
            rsp = await transact(cmd)
            if isinstance(rsp, CmdError):
                raise Exception(rsp)

            while rsp.null is None:
                rsp.merge_from(await rxq.get())

            return rsp

        # --send--> 0101 ~ CMD_PROBE
        rsp = await transact(CmdProbe())

        # <--read-- 0128 ~ CMD_PROBE_CHALLENGE
        # <--read--  + 0122 ~ ProbeChallenge(mac = 00:24:e4:xx:xx:xx, challenge = xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ) # completely random
        if isinstance(rsp, CmdProbeChallenge):
            # --send--> 0128 ~ CMD_PROBE_CHALLENGE
            # --send-->  + 0123 ~ ProbeChallengeResponse(           answer = xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx )
            # --send-->  + 0122 ~ ProbeChallenge(mac = 00:24:e4:xx:xx:xx, challenge = xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx )
            challenge = ProbeChallenge(
                mac=rsp.challenge.mac,
                challenge=secrets.token_bytes(16),
            )
            rsp = await transact(
                CmdProbeChallenge(
                    response=rsp.challenge.make_response(KL_SECRET),
                    challenge=challenge,
                )
            )

            # <--read-- 0101 ~ CMD_PROBE
            # <--read--  + 0123 ~ ProbeChallengeResponse(           answer = xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx )
            # <--read--  + 0101 ~ ProbeReply(vid = 0, pid = 0, name = ScanWatch, mac = 00:24:e4:xx:xx:xx, secret = xxxxxxxxxxxxxxxx, hardVersion = 16777215, mfgId = 001F0080, blVersion = 6, softVersion = 2741, rescueVersion = 16777215)
            # <--read--  + 012C ~ FactoryState(value = 0)
            assert isinstance(rsp, CmdProbe)
            assert rsp.response == challenge.make_response(KL_SECRET)

        print("CONNECTED!")

        rsp = await transact(CmdTrackerUserGet())

        # turn on swim tracking (not persistent?)
        # await transact(CmdSwimStatus(status=SwimStatus(enabled=True)))

        # enable this block to dump flash
        if False:
            REGIONS = (
                # ("all", 0, 0x800000),
                ("dblib_0", 0, 0x2000),
                ("dblib_1", 0x2000, 0x2000),
                ("dblib_2", 0x4000, 0x2000),
                # ("fw_0_hdr", 0x6000, 0x54),
                # ("fw_1_hdr", 0x11f000, 0x54),
                # ("fw_0", 0x6000, 930096),
                # ("fw_1", 0x11f000, 995528),
            )

            for name, addr, length in REGIONS:
                print(f'dumping {name} @ {addr:x} +{length:x}')
                rsp = await transact_until_null(CmdSpiFlash(cmd=SpiFlashCmd(addr=addr, len=length)))

                with open(f'flash_{name}_{addr:x}_{length:x}.bin', 'wb') as f:
                    for c in rsp.chunks:
                        f.write(c.data)

        # enable this block to log battery every 30 seconds forever (not very useful)
        if False:
            with open('bat_log.csv', 'w') as f:
                f.write('time, percent, state, mv\n')
                while True:
                    status = await transact(CmdBatteryStatus())
                    pct = await transact(CmdBatteryPercent())
                    f.write(f'{datetime.now().isoformat()}, {status.status.percent}, {status.status.state}, {pct.voltage.mv}\n')
                    f.flush()
                    await asyncio.sleep(30)

        # enable this block to perform a debug dump with the requested mask
        if True:
            # TODO: debug dump
            # Procedure:
            # CMD_DEBUG_DUMP anchor = 0
            anchor = DebugDumpAnchor(value=0)

            while anchor is not None:
                # CMD_DEBUG_SET mask = 1
                rsp = await transact(CmdDebugSet(mask=DebugDumpMask(mask=DebugMask.DBLIB_DUMP | DebugMask.DBLIB_FORCE_DUMP_ALL | DebugMask.WLOG)))
                # read sequence:
                #   CMD_DEBUG_DUMP DebugDumpType
                #   CMD_DEBUG_DUMP DebugDumpData x 3
                #   CMD_DEBUG_DUMP DebugDumpAnchor + Null
                rsp: CmdDebugDump = await transact_until_null(CmdDebugDump(anchor=anchor))

                if rsp.type is not None:
                    with open(f'debug_dump_{rsp.type.type.name}_{rsp.type.size}.bin', 'wb') as f:
                        for d in rsp.data:
                            f.write(d.buf)

                # repeat until we no longer have an anchor
                anchor = rsp.anchor

            rsp = await transact(CmdDebugDumpAck())

            # reset the mask to the default
            rsp = await transact(CmdDebugSet(mask=DebugDumpMask(mask=DebugMask.DBLIB_DUMP)))

        rsp = await transact(CmdDisconnect())
        assert isinstance(rsp, CmdDisconnect)

        # await asyncio.sleep(1)

        await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(watch_service(), debug=True)
    except asyncio.CancelledError:
        # task is cancelled on disconnect, so we ignore this error
        pass
