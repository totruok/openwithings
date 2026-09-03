#!/usr/bin/env python3
"""
Загрузчик: новые записи из measurements.jsonl → облако Withings (как замер с весов, action=store).
Дальше Health Mate на телефоне сам доносит их до Apple Health.

Состояние: uploaded.json (какие записи уже ушли, по времени замера).
Авторизация: ~/.withings_session.json (sessionid, живёт ≤7 дней) и/или ~/.withings_auth.json
({"email","hash"} — md5 пароля, НЕ сам пароль; создаётся `withings_klsecret.py --save-auth`).
При протухшей сессии перелогинивается по hash.

  python3 withings_upload.py --in measurements.jsonl --userid 12345678 --mac 00:24:e4:xx:xx:xx
  python3 withings_upload.py ... --dry-run
  python3 withings_upload.py ... --mark-uploaded 1788400000   # пометить как уже отправленный (чтобы не дублировать)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

AUTH_URL = "https://scalews.withings.net/cgi-bin/auth"
MEASURE_URL = "https://scalews.withings.com/cgi-bin/measure"
# тип в JSONL → тип Withings; сырые «typeNN» (импеданс) не шлём
TYPES = {"weight": 1, "fat_mass": 8, "hydration": 77, "bone_mass": 88, "muscle_mass": 76}


def log(*a):
    print(datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def post(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())


def login(auth_path: str) -> str:
    with open(auth_path) as f:
        a = json.load(f)
    r = post(AUTH_URL, {"action": "login", "email": a["email"], "hash": a["hash"], "duration": "604800",
                        "os": "ios", "osversion": "15.4", "appname": "wiscaleNG", "apppfm": "ios", "appliver": "5010005"})
    if r.get("status") != 0:
        raise RuntimeError(f"login failed: {r}")
    return r["body"]["sessionid"]


def get_session(session_path: str, auth_path: str, force_new: bool = False) -> str:
    if not force_new and os.path.exists(session_path):
        with open(session_path) as f:
            sid = json.load(f).get("sessionid")
        if sid:
            return sid
    if not os.path.exists(auth_path):
        sys.exit("нет ни сессии, ни auth-файла — сделай `withings_klsecret.py --save-session --save-auth`")
    sid = login(auth_path)
    with open(session_path, "w") as f:
        json.dump({"sessionid": sid, "refreshed": int(time.time())}, f)
    os.chmod(session_path, 0o600)
    log("новая сессия получена по hash")
    return sid


def meas_time(rec: dict) -> int | None:
    """Время замера в epoch. Записи с «временем с включения» (< 1e8) — пропускаем."""
    t = rec["meta"]["time"]
    if isinstance(t, str):
        t = int(t.split()[0])
    return t if t > 100_000_000 else None


def build_measures(rec: dict) -> list[dict]:
    out = []
    for d in rec["raw"]:
        if d["type"] in TYPES.values():
            out.append({"value": d["raw"], "type": d["type"], "unit": d["exponent"]})
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="inp", default="measurements.jsonl")
    p.add_argument("--state", default="uploaded.json")
    p.add_argument("--userid", type=int, required=True)
    p.add_argument("--mac", required=True)
    p.add_argument("--session", default=os.path.expanduser("~/.withings_session.json"))
    p.add_argument("--auth", default=os.path.expanduser("~/.withings_auth.json"))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--mark-uploaded", type=int, action="append", default=[])
    args = p.parse_args()

    state = {"uploaded": []}
    if os.path.exists(args.state):
        with open(args.state) as f:
            state = json.load(f)
    done = set(state["uploaded"])
    for t in args.mark_uploaded:
        done.add(t)
    if args.mark_uploaded:
        state["uploaded"] = sorted(done)
        with open(args.state, "w") as f:
            json.dump(state, f)
        log("помечено как отправленное:", args.mark_uploaded)

    pending = []
    if os.path.exists(args.inp):
        with open(args.inp) as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                t = meas_time(rec)
                if t is None:
                    log("пропуск: время замера относительное:", rec["meta"]["time"])
                    continue
                if t in done:
                    continue
                pending.append((t, rec))
    if not pending:
        log("новых замеров нет")
        return
    log(f"к отправке: {len(pending)}")
    if args.dry_run:
        for t, rec in pending:
            log("  ", datetime.fromtimestamp(t, tz=timezone.utc).isoformat(), build_measures(rec))
        return

    sid = get_session(args.session, args.auth)
    for t, rec in sorted(pending):
        measures = build_measures(rec)
        if not measures:
            log("пропуск: нет известных типов", t)
            continue
        params = {"action": "store", "sessionid": sid, "userid": args.userid, "macaddress": args.mac.lower(),
                  "meastime": t, "devtype": 1, "attribstatus": 0,
                  "measures": json.dumps({"measures": measures}, separators=(",", ":"))}
        r = post(MEASURE_URL, params)
        if r.get("status") in (2555, 401, 100, 293) or (r.get("status") != 0 and "session" in str(r).lower()):
            log("сессия протухла, перелогин:", r)
            sid = get_session(args.session, args.auth, force_new=True)
            params["sessionid"] = sid
            r = post(MEASURE_URL, params)
        if r.get("status") == 0:
            done.add(t)
            state["uploaded"] = sorted(done)
            with open(args.state, "w") as f:
                json.dump(state, f)
            log("отправлено", datetime.fromtimestamp(t, tz=timezone.utc).isoformat(), {m["type"]: m["value"] for m in measures})
        else:
            log("ОШИБКА", t, r)
            sys.exit(1)


if __name__ == "__main__":
    main()
