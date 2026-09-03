#!/usr/bin/env python3
"""
Достать klSecret (ключ для BLE-challenge) своих устройств Withings из облака.
Запускать САМОМУ: спросит email и пароль от аккаунта Withings (getpass, не показывает),
шлёт их только на scalews.withings.net (legacy-API Health Mate, как модуль FHEM 32_withings.pm).

  python3 withings_klsecret.py            # печатает устройства и их секреты
  python3 withings_klsecret.py --raw      # плюс сырой JSON ассоциаций (для отладки)
"""
import argparse
import getpass
import hashlib
import json
import sys
import urllib.parse
import urllib.request

AUTH = "https://scalews.withings.net/cgi-bin/auth"
ACCOUNT = "https://scalews.withings.com/cgi-bin/account"
ASSOC = "https://scalews.withings.com/cgi-bin/association"
APP = {"appname": "hmw", "appliver": "5010005", "apppfm": "web"}


def post(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        txt = r.read().decode()
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        sys.exit(f"не JSON от {url}: {txt[:300]}")


def walk(o, path=""):
    """Найти все ключи, похожие на секреты/ключи, где бы они ни лежали."""
    if isinstance(o, dict):
        for k, v in o.items():
            if any(s in k.lower() for s in ("secret", "klsecret", "kl_secret", "key", "mac", "deviceid", "modelid", "model", "sn", "serial", "name")):
                if not isinstance(v, (dict, list)):
                    yield f"{path}/{k}", v
            yield from walk(v, f"{path}/{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, f"{path}[{i}]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--save-session", action="store_true", help="сохранить sessionid в ~/.withings_session.json")
    ap.add_argument("--save-auth", action="store_true", help="сохранить email+md5(пароля) в ~/.withings_auth.json для перелогина")
    args = ap.parse_args()

    email = input("Withings email: ").strip()
    password = getpass.getpass("Withings password: ")
    r = post(AUTH, {"action": "login", "email": email, "hash": hashlib.md5(password.encode()).hexdigest(),
                    "duration": "604800", "os": "ios", "osversion": "15.4",
                    "appname": "wiscaleNG", "apppfm": "ios", "appliver": "5010005"})
    if r.get("status") != 0 or "sessionid" not in r.get("body", {}):
        sys.exit(f"логин не прошёл: {json.dumps(r)[:400]}")
    sid = r["body"]["sessionid"]
    print("логин ок")

    acc = post(ACCOUNT, {"sessionid": sid, "action": "get", "enrich": "t", **APP})
    body = acc.get("body", {})
    accounts = body.get("account") if isinstance(body, dict) else None
    if isinstance(accounts, dict):
        accounts = [accounts]
    account_ids = []
    if isinstance(accounts, list):
        account_ids = [a.get("id") for a in accounts if isinstance(a, dict) and a.get("id") is not None]
    if not account_ids and isinstance(body, dict):
        account_ids = [v for v in (body.get("id"), body.get("accountid")) if v is not None]
    if not account_ids:
        print("не нашёл accountid, сырой ответ account:", json.dumps(acc)[:1200])
        sys.exit(1)
    print("accountid:", account_ids)
    if args.raw:
        print(json.dumps(acc, indent=1, ensure_ascii=False)[:3000])
    assocs = []
    for account_id in account_ids:
        assoc = post(ASSOC, {"sessionid": sid, "accountid": account_id, "type": "-1", "enrich": "t",
                             "action": "getbyaccountid", **APP})
        if args.raw:
            print(json.dumps(assoc, indent=1, ensure_ascii=False))
        got = assoc.get("body", {}).get("associations", []) if isinstance(assoc.get("body"), dict) else []
        if not got:
            print(f"accountid {account_id}: ассоциаций нет, ответ: {json.dumps(assoc)[:400]}")
        assocs += got
    # список пользователей аккаунта (userid нужен для записи замеров)
    users = post(ACCOUNT, {"sessionid": sid, "accountid": account_ids[0], "recurse_use": "1", "recurse_devtype": "1",
                           "listmask": "5", "allusers": "t", "action": "getuserslist", **APP})
    ulist = users.get("body", {}).get("users", []) if isinstance(users.get("body"), dict) else []
    print(f"пользователей: {len(ulist)}")
    for u in ulist:
        print("   userid:", u.get("id"), "|", u.get("firstname"), u.get("lastname"), "| height:", u.get("height"),
              "| birthdate:", u.get("birthdate"), "| gender:", u.get("gender"))
    if args.save_auth:
        import os
        path = os.path.expanduser("~/.withings_auth.json")
        with open(path, "w") as f:
            json.dump({"email": email, "hash": hashlib.md5(password.encode()).hexdigest()}, f)
        os.chmod(path, 0o600)
        print(f"auth сохранён в {path} (email + md5 пароля, chmod 600) — для перелогина загрузчика")
    if args.save_session:
        import os
        path = os.path.expanduser("~/.withings_session.json")
        with open(path, "w") as f:
            json.dump({"sessionid": sid, "accountid": account_ids[0],
                       "users": [{"id": u.get("id"), "name": f"{u.get('firstname','')} {u.get('lastname','')}".strip()} for u in ulist]}, f)
        os.chmod(path, 0o600)
        print(f"сессия сохранена в {path} (chmod 600, живёт до 7 дней)")

    print(f"ассоциаций: {len(assocs)}")
    for a in assocs:
        dev = a.get("deviceproperties", {}) or {}
        print("-" * 60)
        print("deviceid:", a.get("deviceid"), "| model:", dev.get("model") or dev.get("modelid") or dev.get("type"),
              "| mac:", dev.get("macaddress") or dev.get("mac") or a.get("macaddress"),
              "| sn:", dev.get("sn") or dev.get("serial"))
        found = False
        for k in ("kl", "klsecret", "kl_secret", "secret"):
            if k in a and not isinstance(a[k], (dict, list)):
                print(f"   {k} = {a[k]}")
                found = True
        for k in ("advertise_key", "adv_key", "secret", "kl"):
            if k in dev and not isinstance(dev[k], (dict, list)):
                print(f"   deviceproperties.{k} = {dev[k]}")
                found = True
        for p, v in walk(a):
            if "secret" in p.lower():
                print(f"   {p} = {v}")
                found = True
        if not found:
            print("   секретов в этой ассоциации нет; ключи:", ", ".join(sorted(a.keys())))
            if dev:
                print("   deviceproperties:", ", ".join(sorted(dev.keys())))


if __name__ == "__main__":
    main()
