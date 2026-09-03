# Firmware Parsing

`fw_parser.py` will parse, validate, and extract binaries from a firmware
update.

There are at least 3 known ways of acquiring a firmware update for your *legally
owned and registered* Withings device, which will not be posted here so that the
methods remain available in the future.  The URL containing the firmware will be
on `cdnfw.withings.net` though and the filename contains a (likely) randomized
portion so it is not easy to acquire the URL.

# BLE Communication

The BLE communication method for Withings devices is called WPP.  `wpp.py` is a
module which contains known useful commands and responses and is able to
serialize to and from bytestrings which can be sent/received over BLE.

`scanwatch.py` contains some example usage of these commands to establish a link
to your device.  You must edit `WATCH_SERVICE_UUID`, `WATCH_TX_RX_UUID`, and
`KL_SECRET` for this to work.  The KL Secret used to secure the device pairing
may be acquired in several ways, but the easiest is likely to use Withing's
(undocumented) web APIs.  It is also possible to factory reset your device to
force a new secret to be generated before being stored on Withings servers.

# Databases and Debug Logs

There are a few databases on Withings devices, with the main settings database
being named dblib.  It is not necessary to access the databases directly, as
there are (usually) WPP commands to pull information from the databases in a
cleaner manner.

## dblib

There are 3 copies of dblib:
- 0 seems to contain data which is set from the factory
- 1 and 2 contain runtime data and are written in an alternating manner to prevent data loss

The `dblib.py` script can parse the data in dblib.

The `bat_history.py` script may also be used to convert the watch's own battery
history (logged every 6 hours in dblib) to CSV format.

## wlog

Debug logs may be extracted from the device using a debug dump.  Due to how logs
are stored, this requires a copy of all strings present in the firmware in order
to print the logs.  It is also possible to change the log level on the watch,
but not recommended due to increased flash writes.

## Other databases

There is also a VASISTAS database which stores activity data.

A PLS database exists within dblib whose purpose is unknown.

There is also a FEATURE_TAGS database within dblib which enables and disable
watch settings, optionally on a schedule (start and end time).

# Scale UART

On some Withings scales, there are 3 holes in the bottom which may be used to
connect a TTL (3v3) UART at 1 Mbaud.  These correspond to Tx (from scale), Rx
(to scale), and GND on the scales I have looked at.  The Tx pin is normally
enabled for debug log output, but the Rx pin (and corresponding shell) is
disabled by default.

You should see output such as the following when waking the scale:

```
 ------> ENTERING MAINTASK <-------
WDOG_RSTCNT=0
[BAT] Use default cal
[BAT] 6265 mv (100 %) (MIN 4450 MAX 6000) -> State <OK>
[INITDBLIB] default bank valid
[INITDBLIB] bank1 valid
[INITDBLIB] bank2 valid
[INITDBLIB] Bank courante: 1, address: 0x8000, size 0x8000
[INITDBLIB] Bank autre: 2, address: 0x10000, size 0x8000
[BAT] Use default cal
[LOC] Stored locale: en_EN
[BOOT_TRACE] Boot Counter bridge_weight increased
RESET_REASON = 0x07
[WFTL] Found 4 / 4 blocks for type 0
[WFTL] Found 11 / 11 blocks for type 2
[FLASH CACHE] Init ctx
[info]wlog_init
logs level display:2 store:2
EARLY_RESULT =  Bridge weight
[HANDLE_ZERO] Too noisy (425 25), save=1, ZERO NOT SAVED tare_ko=1
Entering lowpower
wake up in 1 s
== Unset dcdc_sync ==
```

To utilize the UART shell, you must have a TTL UART adapter (such as a FTDI
cable) connected via pogo pins when power is first applied to the scale.  The
scale will detect the pull-up and enable the shell, leading to output such as:


```
BOOTHELLO******** FIRST BOOT ********
[Withings] Bootloader version : 6
[Withings] Compile info : 2018-11-27 17:43:29+01:00 on laptop-GCO
[CRC] EXTERNAL FW1 CHECKING CRC Ok
[CRC] EXTERNAL FW2 CHECKING CRC Ok
[CRC] FWBLK1 CRC OK
[CRC] FWBLK2 CRC OK
[CRC] INTERNAL FW CHECKING
[CRC] match fwblk 1: no
[CRC] match fwblk 2: yes
Reboot to NORMAL_BOOT�
 ------> ENTERING MAINTASK <-------
WDOG_RSTCNT=0
[BAT] Use default cal
[BAT] 6204 mv (100 %) (MIN 4450 MAX 6000) -> State <OK>
[INITDBLIB] default bank valid
[INITDBLIB] bank1 valid
[INITDBLIB] bank2 valid
[INITDBLIB] Bank courante: 2, address: 0x10000, size 0x8000
[INITDBLIB] Bank autre: 1, address: 0x8000, size 0x8000
[BAT] Use default cal
[LOC] Stored locale: en_EN
RESET_REASON = 0x01
[info][DBLIB][SUBSADD] 119 0
[WFTL] Found 4 / 4 blocks for type 0
[WFTL] Found 11 / 11 blocks for type 2
[FLASH CACHE] Init ctx
[info]wlog_init
logs level display:2 store:2
EARLY_RESULT =  First boot
�*****************UART IS CONNECTED***************

shell>help

account_secret
adc
backlight
bkp
boot_trace
bt
...
```
