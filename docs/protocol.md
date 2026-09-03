# WPP as spoken by a Withings Body+ scale

Everything below was observed on a Body+ (WBS05, fw 1651) with `btmon` and the tools in this repo, cross-checked
against the Health Mate constant dump (`references/wpp.json`) and the watch implementations listed in the README.

## BLE surface

| Item | Value |
|---|---|
| Advertised name | `Body+ xx` (last byte of the MAC) |
| Service | `00000020-5749-5448-0005-000000000000` — `5749-5448` is ASCII `WITH`, `0005` is the Withings model id (Body+ = 5; Steel HR = 0x37, ScanWatch = 0x5d, ScanWatch 2 = 0x5e) |
| TX/RX characteristic | `00000024-5749-5448-0005-000000000000`, write + write-without-response + notify (watches use `…0023`) |
| Also advertised | `0x1101` Serial Port Profile — a BR/EDR UUID; BlueZ will try classic Bluetooth unless forced to LE |
| MTU | scale answers Exchange MTU with 185 |
| GAP | Device Name `Body+ xx`, Appearance 0x2000 |

When does the scale advertise:

- **Setup mode**: hold the button underneath ~3 s → display "Start app". Advertises for a couple of minutes. In this
  mode the scale answers `CMD_PROBE` directly (no challenge) and accepts configuration.
- **Bluetooth mode, after every weigh-in**: advertises for a short window (we connected 5–20 s after the first
  advertisement). `CMD_CONNECT_REASON` returns `DEVICE_REQ` (2). Challenge is required.
- **Wi-Fi mode after a weigh-in**: no BLE at all; the scale uploads over Wi-Fi.

## Security

- Any GATT write to the vendor characteristic returns ATT `Insufficient Authentication (0x05)` until the link is
  encrypted. The scale wants **Legacy pairing, Just Works, bonding** (Pairing Response: `Bonding, No MITM, Legacy`).
  Do not initiate pairing yourself before a GATT operation: the scale then goes silent after Pairing Random. Let the
  host elevate security in response to the 0x05 error. A registered agent must answer "yes" to the confirmation.
- Once bonded, later connections start encryption with the LTK immediately (the scale's params: EDIV/Rand as usual).
- On top of the bond, WPP has an application-level challenge (below) keyed by a 32-character ASCII secret the app
  stored in the scale at association time (`kl` in the cloud association record, `advertise_key` alongside it).

## Framing

```
byte 0    0x01                       protocol version
byte 1-2  command  (u16 BE)          bit 0x4000 set = "slave request", initiated by the device
byte 3-4  payload length (u16 BE)
payload   TLV*   type u16 BE | length u16 BE | value
```

Strings and byte arrays inside a TLV are prefixed with one length byte. Multi-byte integers are big-endian.
Notifications are fragmented at the MTU; reassemble by the length field. A response usually echoes the command id;
a list ends with a `Null` TLV (type 256, length 0). Errors come as `CMD_ERROR` (256) with `Cmderror{cmd u16, err i32}`.

## Session, as Health Mate does it

```
connect → wait ~2 s → enable notify
CMD_PROBE (257)          [AppProbe(298){os u8=1 Android, app u8=1 HealthMate, version u32}] [AppProbeOsVersion(2344){u16}]
  ← setup mode:  CMD_PROBE with ProbeReply(257) + FactoryState(300)
  ← normal mode: CMD_PROBE_CHALLENGE (296) with ProbeChallenge(290){mac str, challenge bytes[16]}
CMD_PROBE_CHALLENGE (296) [ProbeChallengeResponse(291){answer = SHA1(challenge || mac_str || kl)}] [ProbeChallenge(290){mac, our 16 random bytes}]
  ← CMD_PROBE with ProbeChallengeResponse (their answer to our challenge, same formula) + ProbeReply
CMD_TIME_SET (1281)      [TimeSet(1281){utc u32, gmtOffset i32, dstChangeTime u32, nextGmtOffset i32}]  ← TimeSetReply(1282){drift i32}
CMD_CONNECT_REASON (273) []                                                                              ← ConnectReason(280){u16}  1 USER_REQ (button), 2 DEVICE_REQ (weigh-in)
CMD_STORED_MEASURE (271) [StoredMeasureAction(276){cmd u8=0 GETSTATE, rc i8}]                            ← StoredMeasureStatus(277){cnt i16, oldestMeasTime i32, wifiConfigured i8}
CMD_STORED_MEASURE (271) [StoredMeasureAction{cmd=1 GETALL}]                                             ← per measurement: StoredMeasureMeta(278) StoredMeasureMetaExtend(299) StoredMeasureData(279)* … Null
CMD_STORED_MEASURE (271) [StoredMeasureAction{cmd=2 DELALL}]                                             ← echo
(optional, setup mode) CMD_WIFI_GET_SETTINGS (260) → TLV 260 with the SSID; CMD_WIFI_SETTINGS (265) [WifiEnable(270){enable i8=0}] → echo; GETSTATE now says wifiConfigured=0
CMD_SYNC_OK (277) []     ← echo        ALWAYS. Skip it and the scale ignores you on the next connection.
CMD_SETUP_OK (275) []    ← echo        in setup-mode sessions; without it the display shows "Setup failed"
CMD_DISCONNECT (272) []  ← echo, then the scale drops the link itself
```

`ProbeReply(257)`: vid u16, pid u16, name str, mac str, secret str (16 hex chars, **not** the `kl` secret),
hardVersion u32, mfgId str, blVersion u32, softVersion u32, rescueVersion u32.

## Stored measurements

```
StoredMeasureMeta(278):       uid u32, userIdCnt u8, userId: u8 count + u32[], attrib u8, time u32
StoredMeasureMetaExtend(299): algo u8        0 = weight only (socks, quick step-off), 3 = impedance measured
StoredMeasureData(279):       value i32, type u16, exponent i16      real value = value * 10^exponent
```

`time` is seconds since epoch once the clock is set; after a battery change it counts from power-on until the
next `CMD_TIME_SET`, after which the scale rebases stored records itself.

Measurement types match the public Withings API: 1 weight kg, 8 fat mass kg, 76 muscle mass kg, 77 hydration kg,
88 bone mass kg. Types 78, 79, 86, 16, 80 come with impedance measurements, values 370–500, exponent 0; they are not
in the public API and look like raw impedance / intermediate values. The scale stores up to 16 measurements.

## Cloud upload in the scale's own format

`POST https://scalews.withings.com/cgi-bin/measure` (form-encoded):

```
action=store  sessionid=<session>  userid=<withings userid>  macaddress=00:24:e4:xx:xx:xx
meastime=<epoch>  devtype=1  attribstatus=0
measures={"measures":[{"value":80123,"type":1,"unit":-3},{"value":1600,"type":8,"unit":-2}, …]}
```

Response `{"status":0}`; the record then shows up in `getmeas` with derived values (fat ratio, fat-free mass) added
by the cloud. Sessions come from `POST https://scalews.withings.net/cgi-bin/auth` with
`action=login email hash=md5(password) duration=604800 os=ios appname=wiscaleNG apppfm=ios appliver=5010005`,
are bound to the client IP, and last up to 7 days. The `kl` secret comes from
`cgi-bin/association action=getbyaccountid enrich=t` (`kl`, plus `deviceproperties.advertise_key`).

## Not yet explored

- `CMD_ASSOCIATION_KEYS_SET` (308) with `AccountKey(309){id u32, secret str}` + `AdvKey(310){secret str}` on a
  factory-reset scale — would remove the need for the cloud login entirely (works on watches, see `references/pairing.rs`).
- `CMD_SCALE_MEDAPP_USER_INFO` (307) `{userId u32, height u16, age u16, sex u8, fatmethod u8}` — user profile for BIA.
- `CMD_DISCONNECT_AND_FAST_ADV` (2323), `CMD_COMM_SUPPORT` (281), the `SCALE_SESSION` (269) string.
