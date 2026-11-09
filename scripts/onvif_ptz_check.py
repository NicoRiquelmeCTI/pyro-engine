# Copyright (C) 2022-2026, Pyronear.

# This program is licensed under the Apache License 2.0.
# See LICENSE or go to <https://opensource.org/licenses/Apache-2.0> for full license details.

"""
Field check for an ONVIF PTZ camera (Hikvision) using the pyro_camera_api ONVIF adapter.

Password is read from the ONVIF_PWD environment variable to keep it out of shell history.

Examples
  export ONVIF_PWD='...'
  python scripts/onvif_ptz_check.py --ip 192.168.1.64 --user pyronear info
  python scripts/onvif_ptz_check.py --ip 192.168.1.64 --user pyronear presets
  python scripts/onvif_ptz_check.py --ip 192.168.1.64 --user pyronear set 0      # save current view as pose 0
  python scripts/onvif_ptz_check.py --ip 192.168.1.64 --user pyronear tour --out /tmp/onvif
"""

# ruff: noqa: T201
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pyro_camera_api"))

from pyro_camera_api.camera.adapters.onvif import (
    NS_MEDIA,
    NS_PTZ,
    OnvifCamera,
    OnvifError,
    _find_local,
    _iter_local,
    _text_local,
)


def run_diag(cam: OnvifCamera) -> None:
    """Try GetPresets with every profile and several XML encodings to find what the firmware accepts."""
    cam.connect()
    body = cam._soap(cam.media_xaddr or "", f"{NS_MEDIA}/GetProfiles", "<trt:GetProfiles/>")
    profiles = []
    for prof in _iter_local(body, "Profiles"):
        ptz_conf = _find_local(prof, "PTZConfiguration")
        profiles.append({
            "token": prof.get("token"),
            "name": _text_local(prof, "Name"),
            "ptz_config": ptz_conf.get("token") if ptz_conf is not None else None,
            "ptz_node": _text_local(ptz_conf, "NodeToken") if ptz_conf is not None else None,
        })
    print("PROFILES", json.dumps(profiles, indent=2))

    for action in ("GetConfigurations", "GetNodes"):
        try:
            b = cam._soap(cam.ptz_xaddr or "", f"{NS_PTZ}/{action}", f"<tptz:{action}/>")
            tokens = [(el.get("token"), _text_local(el, "MaximumNumberOfPresets")) for el in b[0]] if len(b) else []
            print(f"{action} OK", tokens)
        except OnvifError as exc:
            print(f"{action} FAIL", str(exc)[:160])

    encodings = {
        "env_prefix": lambda t: f"<tptz:GetPresets><tptz:ProfileToken>{t}</tptz:ProfileToken></tptz:GetPresets>",
        "default_ns": lambda t: f'<GetPresets xmlns="{NS_PTZ}"><ProfileToken>{t}</ProfileToken></GetPresets>',
        "inline_ns0": lambda t: (
            f'<ns0:GetPresets xmlns:ns0="{NS_PTZ}"><ns0:ProfileToken>{t}</ns0:ProfileToken></ns0:GetPresets>'
        ),
    }
    for prof in profiles:
        for name, build in encodings.items():
            try:
                b = cam._soap(cam.ptz_xaddr or "", f"{NS_PTZ}/GetPresets", build(prof["token"]))
                presets = [(el.get("token"), _text_local(el, "Name")) for el in _iter_local(b, "Preset")]
                print(f"GetPresets OK   profile={prof['token']} enc={name} presets={presets[:10]}")
            except OnvifError as exc:
                print(f"GetPresets FAIL profile={prof['token']} enc={name} {str(exc)[-80:]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--poses", type=int, nargs="+", default=[0, 1, 2, 3])
    parser.add_argument("--preset-offset", type=int, default=1)
    parser.add_argument("--profile-token", default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    sub.add_parser("presets")
    sub.add_parser("diag")
    p_set = sub.add_parser("set")
    p_set.add_argument("pose", type=int)
    p_tour = sub.add_parser("tour")
    p_tour.add_argument("--out", default="onvif_tour")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    password = os.getenv("ONVIF_PWD")
    if not password:
        parser.error("set ONVIF_PWD environment variable")

    cam = OnvifCamera(
        camera_id=args.ip,
        ip_address=args.ip,
        username=args.user,
        password=password,
        cam_type="ptz",
        cam_poses=args.poses,
        port=args.port,
        preset_offset=args.preset_offset,
        profile_token=args.profile_token,
    )

    if args.cmd == "info":
        cam.connect()
        info = {
            "device": cam.get_device_information(),
            "profile_token": cam.profile_token,
            "media_xaddr": cam.media_xaddr,
            "ptz_xaddr": cam.ptz_xaddr,
            "clock_offset_s": cam._clock_offset.total_seconds(),
            "ptz_status": cam.get_ptz_status(),
        }
        print(json.dumps(info, indent=2, default=str))
    elif args.cmd == "diag":
        run_diag(cam)
    elif args.cmd == "presets":
        print(json.dumps(cam.get_ptz_preset(), indent=2))
    elif args.cmd == "set":
        print(json.dumps(cam.set_ptz_preset(idx=args.pose), indent=2))
    elif args.cmd == "tour":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for pose in args.poses:
            t0 = time.monotonic()
            res = cam.move_camera("ToPos", idx=pose)
            elapsed = time.monotonic() - t0
            img = cam.capture()
            path = out / f"pose_{pose}.jpg"
            if img is not None:
                img.save(path)
            print(
                f"pose={pose} token={res['preset_token']} move={elapsed:.1f}s "
                f"status={res['status']} snapshot={'OK ' + str(path) if img else 'FAIL'}"
            )
        cam.move_camera("ToPos", idx=args.poses[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
