# BlueZ pitfalls, in the order we hit them

Every item below cost real time on a Raspberry Pi 4 (BlueZ 5.82, kernel 6.18, bleak). Each is a distinct failure with
a distinct fix; several look identical from the outside ("the scale disconnects").

1. **`br-connection-profile-unavailable` / `br-connection-create-socket` on connect.** The scale advertises the
   Serial Port Profile UUID, BlueZ decides it is dual-mode and connects over BR/EDR. `PreferredBearer` does not exist
   in 5.82. Fix: `ControllerMode = le` in `/etc/bluetooth/main.conf`, restart bluetoothd.

2. **Nothing answers the CCCD write; the link dies 30 s later with "Unlikely Error".** Not a hang: the scale returns
   ATT `Insufficient Authentication` and BlueZ tries to pair. With no agent, pairing fails ("No agent available") and
   the scale drops the link. Fix: run an agent (`tools/agent.sh`).

3. **`bluetoothctl agent NoInputNoOutput` says "Agent is already registered".** bluetoothctl registers a
   KeyboardDisplay agent at startup, and with that capability BlueZ asks for confirmation. Start it as
   `bluetoothctl -a NoInputNoOutput` instead.

4. **Even then the agent prints `[agent] Accept pairing (yes/no):` and waits.** Something must type `yes`. The
   agent script polls its own output and answers.

5. **Explicit `Pair()` before any GATT operation: SMP Confirm/Random exchanged, then silence, supervision timeout.**
   The scale only completes pairing when the host elevates security in reaction to the 0x05 error. Do not pair
   proactively.

6. **After a successful pairing, encryption start times out (`Encryption Change: Connection Timeout`), or GATT
   discovery dies after 2 s.** The scale answers ATT requests in 250–500 ms and the Linux default supervision
   timeout is 420 ms (`0x2a`). Phones use 2–20 s. Fix: raise it — but see 7.

7. **debugfs `supervision_timeout` and main.conf `[LE]` values are ignored.** The kernel keeps per-device
   `hci_conn_params` for an address it has ever tried to connect to (visible in
   `/sys/kernel/debug/bluetooth/hci0/device_list`), created with the defaults in force at that time. They survive
   bluetoothd restarts and adapter power cycles, and `bluetoothctl remove` only reaches the kernel when bluetoothd
   still has the device object. Fix: `MGMT_OP_LOAD_CONN_PARAM` for the address (`tools/mgmt_fix.py`), or edit
   `[ConnectionParameters]` in `/var/lib/bluetooth/<adapter>/<device>/info` once a bond exists and restart
   bluetoothd.

8. **Python cannot bind an MGMT socket** (`bind(): wrong format`); do it with ctypes (`tools/mgmt_fix.py`).

9. **"Connection Failed to be Established (0x3e)" or a connection with zero packets right after a session.** In our
   traces this followed sessions that were closed without `CMD_SYNC_OK`; after fixing the session end it stopped.
   Also possible: connecting to a stale advertisement after the scale went back to sleep. Retry on a fresh advert.

10. **bleak connect with the scanner still running never issues LE Create Connection.** The controller filters
    duplicate advertisements, so BlueZ's "connect when next seen" path waits forever. Stop the scanner, connect at
    once, restart the scanner after the session.

11. **A session that ends only with `CMD_DISCONNECT` leaves the scale saying "Setup failed" and sulking.** Send
    `CMD_SYNC_OK` always and `CMD_SETUP_OK` in setup-mode sessions; the scale then terminates the link itself with
    "Remote User Terminated Connection".

12. **The scale's own connection parameter request (15–30 ms, 2 s) is stored by BlueZ in the bond file and reused
    for the next connection.** Harmless once everything else is right; if a fresh connection dies at the first
    packets, compare `LE Connection Complete` parameters in `btmon` between a good and a bad session.

Diagnostics that actually showed the truth: `sudo btmon -w capture.snoop` running the whole time, then
`btmon -r capture.snoop | grep -E "SMP:|ATT:|Reason:|Supervision"`. Everything else was guessing.
