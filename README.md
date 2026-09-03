# openwithings

Talk to Withings scales over Bluetooth LE from Linux. No Health Mate app, no Wi-Fi, no cloud required.

Not affiliated with, endorsed by, or supported by Withings. Reverse-engineered for interoperability with hardware you own.

## What it does

A Withings Body+ (WBS05) in Bluetooth mode advertises for a short window after every weigh-in and waits for "its"
phone. `openwithings` makes a Raspberry Pi be that phone:

1. listens for the scale's advertisement,
2. connects with the bond it created once (Legacy Just Works pairing),
3. speaks WPP, the Withings proprietary protocol: probe, challenge/response with the account secret, time sync,
4. pulls every stored measurement (weight, fat mass, muscle mass, hydration, bone mass, raw impedance), writes them
   to a JSONL file and clears the scale's memory,
5. closes the session the way Health Mate does, so the scale stays happy,
6. optionally pushes the measurements to the Withings cloud in the scale's own upload format, from where Health Mate
   still feeds Apple Health, and tools like [withings-sync](https://github.com/jaroslawhartman/withings-sync) feed
   Garmin.

Tested on: Body+ (WBS05, firmware 1651), Raspberry Pi 4, Debian 13, BlueZ 5.82, kernel 6.18, python 3.13 + bleak.

Status: working end to end for one scale model, as a set of scripts. A proper library layout is the next step.

## Why

Withings scales are good hardware locked to an app and a Wi-Fi network. If you travel, you re-enter Wi-Fi in every
flat. If you don't want the app, you have no data. The protocol is readable once the BLE bond is in place; several
people had already reverse-engineered it for the watches. This project fills the gap for scales.

## Step-by-step setup

Read the whole list once before starting. Steps 1–3 are done once per Pi, steps 4–7 once per scale, step 8 is the
steady state. Where a step exists because of a specific BlueZ failure, the number in brackets points to
`docs/bluez-pitfalls.md`.

### 1. Requirements

- A Linux box with a Bluetooth LE adapter within a few metres of the scale. Raspberry Pi 4 onboard radio works
  when the Pi is on Ethernet; on 2.4 GHz Wi-Fi the onboard radio is known to fail LE connections, use Ethernet or a
  USB dongle.
- BlueZ 5.8x, `bluetoothctl`, `btmon` (package `bluez`), `sudo`.
- Python 3.11+.
- Your Withings account credentials (only for step 5; they never leave your machine except to Withings' own API).

```bash
git clone <this repo> && cd openwithings
python3 -m venv venv && ./venv/bin/pip install bleak
```

### 2. Make BlueZ LE-only and slow down its impatience [pitfalls 1, 6]

Edit `/etc/bluetooth/main.conf`:

```ini
[General]
ControllerMode = le

[LE]
MinConnectionInterval=24
MaxConnectionInterval=40
ConnectionLatency=0
ConnectionSupervisionTimeout=500
```

The scale also advertises a classic Serial Port profile and BlueZ would otherwise connect over BR/EDR; and the scale
answers ATT requests in 250–500 ms, which the default 420 ms supervision timeout does not survive.

```bash
sudo systemctl restart bluetooth
bluetoothctl power on
```

### 3. Start a pairing agent that says yes [pitfalls 2–4]

The first GATT write is refused with "Insufficient Authentication"; BlueZ then pairs (Legacy Just Works) and needs an
agent to accept. `bluetoothctl`'s default agent asks a question nobody answers, so:

```bash
./tools/agent.sh &            # bluetoothctl -a NoInputNoOutput + auto "yes"; leave it running
```

### 4. Find the scale and talk to it once (setup mode)

Hold the button on the underside of the scale for ~3 s until the display shows "Start app". It now advertises for a
couple of minutes and answers without a challenge.

```bash
./venv/bin/python tools/withings_probe.py scan                      # prints the MAC, e.g. 00:24:E4:xx:xx:xx
./venv/bin/python tools/withings_probe.py probe --address 00:24:E4:xx:xx:xx
```

Expected: `ProbeReply` with name, firmware, MAC; `StoredMeasureStatus` with the count of stored measurements and
`wifiConfigured`; a list of measurements if any. Pairing happens automatically during this first probe; afterwards
`bluetoothctl info <MAC>` shows `Paired: yes, Bonded: yes`.

If the connection dies within two seconds, or the scale never sends a packet, the kernel is still using old
per-device connection parameters [pitfall 7]:

```bash
sudo python3 tools/mgmt_fix.py 00:24:E4:xx:xx:xx    # loads 30–50 ms / 5 s for this address into the kernel
```

and press the button again. The display saying "Setup failed" after a probe is normal at this stage: the probe does
not finish the setup handshake; the daemon does.

### 5. Get the account secret the scale will challenge you with [protocol: Security]

Outside setup mode the scale demands `SHA1(challenge + mac + kl)`, where `kl` is a 32-character secret Health Mate
stored in the scale when it was first set up. It lives only in the Withings cloud. Run this **on your own computer**;
it asks for your Withings password, sends only its md5 to Withings' legacy API, and prints the secret:

```bash
python3 tools/withings_klsecret.py --save-auth
```

Note the `kl` line for your scale's MAC and your `userid`. `--save-auth` writes `~/.withings_auth.json`
(email + md5 of the password, mode 600); copy that file to the Pi if you want the cloud upload of step 7. Sessions
are bound to the client IP, so the Pi must log in by itself.

### 6. Run the collector and switch the scale to Bluetooth mode

```bash
./venv/bin/python tools/withings_daemon.py --address 00:24:E4:xx:xx:xx \
    --secret <kl> --delete --disable-wifi --setup-ok --out measurements.jsonl
```

Press the button once more (3 s, "Start app"). In this setup-mode session the daemon reads and clears the stored
measurements, sends `WIFI_SETTINGS enable=0`, confirms `wifiConfigured: 0`, and closes with `SYNC_OK`, `SETUP_OK`,
`DISCONNECT`. The display should not say "Setup failed" any more. From now on the scale advertises after every
weigh-in and the daemon handles it without the button.

Run it under `setsid nohup … &` or a systemd unit; it restarts its scanner on its own and retries a failed connection
on the next fresh advertisement.

### 7. Optional: feed the Withings cloud (and through it Apple Health, Garmin, …)

The cloud accepts measurements in the scale's own format. Put `~/.withings_auth.json` from step 5 on the Pi and add:

```bash
    --upload-args "--userid <userid> --mac 00:24:e4:xx:xx:xx"
```

The daemon then calls `tools/withings_upload.py` after every session and every 10 minutes (for intermittent
internet). Uploaded records are tracked in `uploaded.json` by measurement time, so nothing is sent twice. Health Mate
on the phone picks them up from the cloud exactly as if the scale had uploaded them, and writes them to Apple Health.

### 8. Steady state

Step on the scale barefoot and stay until it shows the body-composition screens (a quick step-off or socks gives
weight only, `algo: 0`). Within ~20 s the daemon logs the session and appends to `measurements.jsonl`:

```json
{"received_at": "2026-09-03T09:32:19+00:00",
 "meta": {"userId": [12345678], "time": "1788400000 (2026-09-03T01:46:40+00:00)"},
 "values": {"weight": 80.123, "fat_mass": 16.0, "hydration": 45.0, "bone_mass": 3.1, "muscle_mass": 60.0,
            "type78": 499, "type79": 477, "type86": 453, "type16": 441, "type80": 407}}
```

After a battery change the scale's clock restarts from zero; the daemon sets the time in every session and the scale
rebases stored records, so timestamps stay correct.

### Troubleshooting

Run `sudo btmon -w capture.snoop` in the background during any experiment and read it with
`btmon -r capture.snoop | grep -E "SMP:|ATT:|Reason:|Supervision"`. Then match what you see against
`docs/bluez-pitfalls.md`. Everything else is guessing.

### 9. Run it as a service (systemd, survives reboots)

Copy `tools/run-daemon.sh.example` to `~/withings_ble/run-daemon.sh`, fill in your MAC, `kl` secret and
userid, `chmod 700` it (this keeps the secret out of the unit file and out of git). Then install
`tools/openwithings.service` as a user unit:

```bash
mkdir -p ~/.config/systemd/user
cp tools/openwithings.service ~/.config/systemd/user/
loginctl enable-linger "$USER"          # so it runs without an active login session
systemctl --user daemon-reload
systemctl --user enable --now openwithings.service
systemctl --user status openwithings.service
```

Logs go to `~/withings_ble/daemon.log`. The BlueZ settings from step 2 and the bond from step 4 persist
across reboots, so nothing else needs re-doing.

## Layout

- `tools/withings_probe.py` — WPP framing, TLV decoding, probe/challenge, stored-measure commands, pairing helper.
- `tools/withings_daemon.py` — the collector: scan, connect, session, JSONL, cloud upload.
- `tools/withings_upload.py` — measurements → Withings cloud (`cgi-bin/measure action=store`, the scale's own format).
- `tools/withings_klsecret.py` — fetch the scale's `kl` secret and your userid from the Withings cloud.
- `tools/mgmt_fix.py`, `tools/agent.sh` — BlueZ plumbing (per-device connection parameters, auto-accepting agent).
- `tools/openwithings.service`, `tools/run-daemon.sh.example` — systemd user unit to run the collector on boot.
- `docs/protocol.md` — everything we know about WPP as spoken by the scale.
- `docs/bluez-pitfalls.md` — the dozen ways a Linux box fails to talk to this scale, and the fix for each.
- `references/` — third-party sources the work is built on (see `references/SOURCES.md`).

## Standing on

- [DavidVentura/withouthings](https://github.com/DavidVentura/withouthings) and the
  [blog post](https://blog.davidv.dev/posts/withings-re/) — WPP framing, SHA1 challenge, and the full constant dump
  from Health Mate (`references/wpp.json`).
- [SureshotM6/scanwatch_ble](https://github.com/SureshotM6/scanwatch_ble) — python WPP for ScanWatch, and the one
  comment that recorded the Body+ service UUID.
- [Gadgetbridge](https://codeberg.org/Freeyourgadget/Gadgetbridge) Withings Steel HR support — bonding style,
  session sequence, the "always send SYNC_OK" rule.
- [loredous/hardware_teardowns](https://github.com/loredous/hardware_teardowns) and
  [JGaudette/wiscale](https://github.com/JGaudette/wiscale) — the cloud `store` call parameters.

## Roadmap

- Library layout (`openwithings.wpp`, `openwithings.ble`, `openwithings.cloud`, device drivers) and a CLI.
- Own account key via `CMD_ASSOCIATION_KEYS_SET` after a factory reset, so no cloud login is needed at all.
- Other scales (Body, Body Cardio, Body Comp/Scan share the protocol; only the service UUID model byte differs) and,
  with community help, the watches and BPM.
- systemd unit, Home Assistant / MQTT output.

License: MIT.
