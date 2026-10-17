#!/usr/bin/env python3
"""
Облачная сессия весов, открытая «от имени весов», и её доставка в весы по BLE — так делает Health Mate.

Весы в Wi-Fi-режиме сами ходят в scalews (старый протокол WBS01/WS-30) и из ответа session/new узнают
пользователей. В Bluetooth-режиме то же самое делает приложение: открывает сессию за весы и заливает ответ
в весы командой CMD_SCALE_SESSION (269). Из этого ответа весы берут всё, что помнят о людях: id, 3-буквенное
имя на экране, средний вес (по нему узнают, кто встал), рост, возраст, пол, метод расчёта жира (без них нет
состава тела), плюс язык, время и часовой пояс. Команды 276/307 Body+ не поддерживает (err −3).

Облако (как в Health Mate 26.42, mlj/hih/xc8/i5m):
  POST /cgi-bin/once    action=get                                   → {"body": {"once": "…"}}
  POST /cgi-bin/session action=new auth=<mac> hash=md5("<mac>:<ProbeReply.secret>:<once>")
                        duration=600 currentfw=<softVersion> mfgid=int(<mfgId>, 16) [batterylvl] battery_state=-1
                        [feature_mask] enrich=t last_used_network=2 httpslink=3
                                                                     → {"status":0,"body":{"sessionid", "sp": {"users": […]}, …}}
`secret` — поле ProbeReply.secret (16 hex), НЕ kl. Логин в аккаунт не нужен.

BLE (SendSessionConversation, f99 case 8, yqx.k):
  data = '{"status":0,"body":' + compact(body) + '}' + '\\0'   (два символа: обратный слэш и ноль — так в APK)
  data режется на куски ≤64 байт → по TLV ScaleSession(274){string} на кусок, в конце TLV Null(256);
  TLV раскладываются по сообщениям CMD_SCALE_SESSION не длиннее 200 байт (по 2 куска на сообщение);
  сообщения уходят подряд, ответ — одно сообщение 269 (или CMD_ERROR).

  python3 withings_scalesession.py --mac 00:24:e4:xx:xx:xx --secret <ProbeReply.secret> --mfgid 000EC025 --fw 1651
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import urllib.parse
import urllib.request

BASE = "https://scalews.withings.net/cgi-bin"
CMD_SCALE_SESSION = 269
T_SCALE_SESSION = 274
T_NULL = 256
CHUNK = 64        # байт данных на один TLV ScaleSession
MSG_LIMIT = 200   # максимум байт на одно WPP-сообщение (заголовок 5 + TLV)


def _post(path: str, timeout: float, **data) -> dict:
    data = {k: v for k, v in data.items() if v is not None}
    req = urllib.request.Request(f"{BASE}/{path}", data=urllib.parse.urlencode(data).encode(),
                                 headers={"User-Agent": "Withings UserAgent",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def open_session(mac: str, secret: str, mfgid: str, fw: int, battery: int | None = None,
                 feature_mask: int | None = None, timeout: float = 15.0) -> dict:
    """Открыть сессию весов; вернуть body ответа session/new. mfgid — как в ProbeReply (hex-строка)."""
    once = _post("once", timeout, action="get")["body"]["once"]
    h = hashlib.md5(f"{mac}:{secret}:{once}".encode()).hexdigest()
    js = _post("session", timeout, action="new", auth=mac, hash=h, duration="600", currentfw=str(fw),
               mfgid=str(int(mfgid, 16)), batterylvl=None if battery is None else str(battery), battery_state="-1",
               feature_mask=None if feature_mask is None else str(feature_mask), enrich="t",
               last_used_network="2", httpslink="3")
    if js.get("status") != 0 or "sessionid" not in js.get("body", {}):
        raise RuntimeError(f"session/new: status {js.get('status')}")
    return js["body"]


def close_session(sessionid: str, timeout: float = 15.0) -> None:
    _post("session", timeout, action="delete", sessionid=sessionid)


def session_string(body: dict) -> str:
    return '{"status":0,"body":' + json.dumps(body, ensure_ascii=False, separators=(",", ":")) + "}" + "\\0"


def session_messages(body: dict) -> list[bytes]:
    """Готовые WPP-сообщения CMD_SCALE_SESSION для заливки сессии в весы."""
    chunks, cur = [], ""
    for ch in session_string(body):
        if len((cur + ch).encode()) > CHUNK:
            chunks.append(cur)
            cur = ch
        else:
            cur += ch
    if cur:
        chunks.append(cur)
    tlvs = []
    for c in chunks:
        b = c.encode()
        tlvs.append(struct.pack(">HHB", T_SCALE_SESSION, len(b) + 1, len(b)) + b)
    tlvs.append(struct.pack(">HH", T_NULL, 0))
    msgs, cur, size = [], [], 5
    for t in tlvs:
        if cur and size + len(t) > MSG_LIMIT:
            msgs.append(cur)
            cur, size = [], 5
        cur.append(t)
        size += len(t)
    msgs.append(cur)
    return [b"\x01" + struct.pack(">HH", CMD_SCALE_SESSION, sum(map(len, m))) + b"".join(m) for m in msgs]


def describe(body: dict) -> str:
    users = [f"{u.get('id')} {u.get('sn')} wt={u.get('wt')} ht={u.get('ht')} age={u.get('agt')} "
             f"sx={u.get('sx')} fm={u.get('fm')}" for u in body.get("sp", {}).get("users", [])]
    return "; ".join(users) or "no users"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mac", required=True, help="MAC как его называют сами весы (ProbeReply.mac), нижний регистр")
    p.add_argument("--secret", required=True, help="ProbeReply.secret")
    p.add_argument("--mfgid", required=True)
    p.add_argument("--fw", type=int, required=True)
    a = p.parse_args()
    body = open_session(a.mac, a.secret, a.mfgid, a.fw)
    close_session(body["sessionid"])
    msgs = session_messages(body)
    print("users:", describe(body))
    print(f"to scale: {len(session_string(body))} chars → {len(msgs)} message(s) of {[len(m) for m in msgs]} bytes")
    body["sessionid"] = body["sessionid"][:4] + "…"
    print(json.dumps(body, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
