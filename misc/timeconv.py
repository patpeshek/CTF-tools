#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
timeconv.py — unix-время ↔ дата, часовые пояса, день недели.
Полезно для OSINT/forensic-задач про метаданные и «в какую дату это было».

  python timeconv.py --ts 1274552191
  python timeconv.py --ts 1274552191000        # миллисекунды определятся сами
  python timeconv.py --date "2010-05-22 20:16:31" --tz +4
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import datetime as dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ts", type=int)
    ap.add_argument("--date")
    ap.add_argument("--tz", type=float, default=0, help="смещение часового пояса, например +3")
    args = ap.parse_args()

    if args.ts is not None:
        ts = args.ts
        if ts > 10_000_000_000:
            ts = ts / 1000
            print("[i] похоже на миллисекунды")
        utc = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
        print("UTC:  ", utc.strftime("%Y-%m-%d %H:%M:%S"), utc.strftime("%A"))
        local = utc.astimezone(dt.timezone(dt.timedelta(hours=args.tz)))
        print(f"UTC{args.tz:+g}:", local.strftime("%Y-%m-%d %H:%M:%S"))
        print("unix: ", int(ts))
        print("ISO:  ", utc.isoformat())
    elif args.date:
        d = dt.datetime.strptime(args.date, "%Y-%m-%d %H:%M:%S")
        d = d.replace(tzinfo=dt.timezone(dt.timedelta(hours=args.tz)))
        print("unix:", int(d.timestamp()))
        print("UTC: ", d.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %A"))
    else:
        ap.error("нужен --ts или --date")


if __name__ == "__main__":
    main()
