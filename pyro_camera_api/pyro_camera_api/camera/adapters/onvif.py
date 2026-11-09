# Copyright (C) 2022-2026, Pyronear.

# This program is licensed under the Apache License 2.0.
# See LICENSE or go to <https://opensource.org/licenses/Apache-2.0> for full license details.

"""
Generic ONVIF Profile S adapter (PTZ + snapshot), tested target: Hikvision PTZ domes.

Design notes
- Plain SOAP 1.2 over requests with WS-Security UsernameToken (PasswordDigest).
  No zeep / WSDL files, so the Docker image keeps the same dependencies.
- Connection is lazy: the camera is registered even if it is offline at boot,
  and the ONVIF handshake is retried on the next call.
- Pyronear poses are mapped to ONVIF preset tokens:
    * explicit `preset_tokens` list aligned with `poses`, or
    * token = str(pose + preset_offset). Hikvision presets start at 1, so the
      default offset is 1 (pose 0 -> preset "1", ..., pose 3 -> preset "4").
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import logging
import os
import threading
import time
import xml.etree.ElementTree as ET
from io import BytesIO
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit
from xml.sax.saxutils import escape

import requests
import urllib3
from PIL import Image
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from pyro_camera_api.camera.base import BaseCamera, PTZMixin

__all__ = ["OnvifCamera", "OnvifError"]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

NS_SOAP = "http://www.w3.org/2003/05/soap-envelope"
NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
PWD_DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"  # noqa: S105
NONCE_B64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

NS_DEVICE = "http://www.onvif.org/ver10/device/wsdl"
NS_MEDIA = "http://www.onvif.org/ver10/media/wsdl"
NS_PTZ = "http://www.onvif.org/ver20/ptz/wsdl"
NS_SCHEMA = "http://www.onvif.org/ver10/schema"


class OnvifError(RuntimeError):
    """Raised on transport errors or SOAP faults returned by the camera."""


# ----------------------------------------------------------------------
# XML helpers (namespace agnostic lookups, devices differ on prefixes)
# ----------------------------------------------------------------------


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _iter_local(node: ET.Element, name: str):
    for el in node.iter():
        if _local(el.tag) == name:
            yield el


def _find_local(node: ET.Element, name: str) -> Optional[ET.Element]:
    return next(_iter_local(node, name), None)


def _text_local(node: ET.Element, name: str) -> Optional[str]:
    el = _find_local(node, name)
    if el is None or el.text is None:
        return None
    return el.text.strip()


def _float_attr(el: Optional[ET.Element], attr: str) -> Optional[float]:
    if el is None:
        return None
    raw = el.get(attr)
    try:
        return float(raw) if raw is not None else None
    except ValueError:
        return None


class OnvifCamera(BaseCamera, PTZMixin):
    """ONVIF PTZ camera adapter exposing the same surface as the Reolink and Linovision adapters."""

    def __init__(
        self,
        camera_id: str,
        ip_address: str,
        username: str,
        password: str,
        cam_type: str = "ptz",
        cam_poses: Optional[List[int]] = None,
        cam_azimuths: Optional[List[int]] = None,
        port: int = 80,
        protocol: str = "http",
        verify_tls: bool = False,
        timeout: float = 5.0,
        profile_token: Optional[str] = None,
        profile_index: int = 0,
        preset_tokens: Optional[Sequence[Any]] = None,
        preset_offset: int = 1,
        snapshot_url: Optional[str] = None,
        rewrite_xaddrs: bool = True,
        move_timeout_s: float = 20.0,
        focus_position: Optional[int] = None,
    ) -> None:
        super().__init__(camera_id=camera_id, cam_type=cam_type)
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.cam_poses = list(cam_poses) if cam_poses else []
        self.cam_azimuths = list(cam_azimuths) if cam_azimuths else []
        self.port = int(port)
        self.protocol = protocol
        self.verify_tls = verify_tls
        self.timeout = float(timeout)
        self.profile_index = int(profile_index)
        self.preset_offset = int(preset_offset)
        self.rewrite_xaddrs = rewrite_xaddrs
        self.move_timeout_s = float(move_timeout_s)
        # Kept for parity with other adapters, focus is not driven through ONVIF yet
        self.focus_position = focus_position

        if preset_tokens is not None and self.cam_poses and len(preset_tokens) != len(self.cam_poses):
            raise ValueError("preset_tokens must have the same length as poses")
        self.preset_tokens = [str(t) for t in preset_tokens] if preset_tokens is not None else None

        self._base = f"{self.protocol}://{self.ip_address}:{self.port}"
        self.device_xaddr = f"{self._base}/onvif/device_service"
        self.media_xaddr: Optional[str] = None
        self.ptz_xaddr: Optional[str] = None
        self.profile_token: Optional[str] = profile_token
        self._profile_token_forced = profile_token is not None
        self.snapshot_url: Optional[str] = snapshot_url
        self._snapshot_url_forced = snapshot_url is not None

        self._clock_offset = dt.timedelta(0)
        self._connected = False
        self._lock = threading.RLock()
        self._session = requests.Session()
        self._preset_cache: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # SOAP transport
    # ------------------------------------------------------------------

    def _security_header(self) -> str:
        nonce = os.urandom(16)
        created = (dt.datetime.now(dt.timezone.utc) + self._clock_offset).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        digest = base64.b64encode(
            hashlib.sha1(nonce + created.encode("utf-8") + self.password.encode("utf-8")).digest()  # noqa: S324
        ).decode("ascii")
        return (
            f'<wsse:Security s:mustUnderstand="1" xmlns:wsse="{NS_WSSE}" xmlns:wsu="{NS_WSU}">'
            "<wsse:UsernameToken>"
            f"<wsse:Username>{escape(self.username)}</wsse:Username>"
            f'<wsse:Password Type="{PWD_DIGEST}">{digest}</wsse:Password>'
            f'<wsse:Nonce EncodingType="{NONCE_B64}">{base64.b64encode(nonce).decode("ascii")}</wsse:Nonce>'
            f"<wsu:Created>{created}</wsu:Created>"
            "</wsse:UsernameToken>"
            "</wsse:Security>"
        )

    def _envelope(self, body: str, auth: bool = True) -> str:
        header = f"<s:Header>{self._security_header()}</s:Header>" if auth else ""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<s:Envelope xmlns:s="{NS_SOAP}" xmlns:tds="{NS_DEVICE}" xmlns:trt="{NS_MEDIA}" '
            f'xmlns:tptz="{NS_PTZ}" xmlns:tt="{NS_SCHEMA}">'
            f"{header}<s:Body>{body}</s:Body></s:Envelope>"
        )

    def _soap(self, xaddr: str, action: str, body: str, auth: bool = True) -> ET.Element:
        headers = {"Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"'}
        try:
            resp = self._session.post(
                xaddr,
                data=self._envelope(body, auth=auth).encode("utf-8"),
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            raise OnvifError(f"ONVIF transport error on {action.rsplit('/', 1)[-1]}: {exc}") from exc

        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            raise OnvifError(f"Invalid SOAP response, status {resp.status_code}, body {resp.text[:300]}") from exc

        fault = _find_local(root, "Fault")
        if fault is not None or resp.status_code >= 400:
            reason = _text_local(root, "Text") or _text_local(root, "faultstring") or resp.text[:300]
            subcode = None
            sub = _find_local(root, "Subcode")
            if sub is not None:
                subcode = _text_local(sub, "Value")
            raise OnvifError(
                f"SOAP fault on {action.rsplit('/', 1)[-1]} (HTTP {resp.status_code}, {subcode}): {reason}"
            )

        body_el = _find_local(root, "Body")
        return body_el if body_el is not None else root

    def _rewrite(self, xaddr: Optional[str]) -> Optional[str]:
        """Cameras behind NAT/VPN often advertise an unreachable host in XAddrs, keep only the path."""
        if not xaddr or not self.rewrite_xaddrs:
            return xaddr
        parts = urlsplit(xaddr)
        base = urlsplit(self._base)
        return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, parts.fragment))

    # ------------------------------------------------------------------
    # Connection bootstrap
    # ------------------------------------------------------------------

    def _sync_clock(self) -> None:
        """WS-Security digests are rejected when clocks drift, so we sign with the camera clock."""
        try:
            body = self._soap(
                self.device_xaddr,
                f"{NS_DEVICE}/GetSystemDateAndTime",
                "<tds:GetSystemDateAndTime/>",
                auth=False,
            )
            utc = _find_local(body, "UTCDateTime")
            if utc is None:
                return
            date_el, time_el = _find_local(utc, "Date"), _find_local(utc, "Time")
            if date_el is None or time_el is None:
                return
            cam_now = dt.datetime(
                int(_text_local(date_el, "Year") or 1970),
                int(_text_local(date_el, "Month") or 1),
                int(_text_local(date_el, "Day") or 1),
                int(_text_local(time_el, "Hour") or 0),
                int(_text_local(time_el, "Minute") or 0),
                int(_text_local(time_el, "Second") or 0),
                tzinfo=dt.timezone.utc,
            )
            self._clock_offset = cam_now - dt.datetime.now(dt.timezone.utc)
            if abs(self._clock_offset.total_seconds()) > 5:
                logger.warning(
                    "[%s] Camera clock drift %.0fs, compensating in WS-Security",
                    self.camera_id,
                    self._clock_offset.total_seconds(),
                )
        except OnvifError as exc:
            logger.debug("[%s] GetSystemDateAndTime failed, keeping local clock: %s", self.camera_id, exc)

    def connect(self, force: bool = False) -> None:
        with self._lock:
            if self._connected and not force:
                return

            self._sync_clock()

            caps = self._soap(
                self.device_xaddr,
                f"{NS_DEVICE}/GetCapabilities",
                "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
            )
            media = _find_local(caps, "Media")
            ptz = _find_local(caps, "PTZ")
            self.media_xaddr = self._rewrite(_text_local(media, "XAddr") if media is not None else None)
            self.ptz_xaddr = self._rewrite(_text_local(ptz, "XAddr") if ptz is not None else None)

            if not self.media_xaddr:
                raise OnvifError("Camera does not expose an ONVIF Media service")
            if self.cam_type == "ptz" and not self.ptz_xaddr:
                raise OnvifError("Camera configured as ptz but does not expose an ONVIF PTZ service")

            if not self._profile_token_forced:
                self.profile_token = self._select_profile()

            self._connected = True
            logger.info(
                "[%s] ONVIF connected, profile=%s, media=%s, ptz=%s",
                self.camera_id,
                self.profile_token,
                self.media_xaddr,
                self.ptz_xaddr,
            )

    def _select_profile(self) -> str:
        body = self._soap(self.media_xaddr or "", f"{NS_MEDIA}/GetProfiles", "<trt:GetProfiles/>")
        profiles = [p for p in _iter_local(body, "Profiles") if p.get("token")]
        if not profiles:
            raise OnvifError("No ONVIF media profile found")

        if self.cam_type == "ptz":
            with_ptz = [p for p in profiles if _find_local(p, "PTZConfiguration") is not None]
            if with_ptz:
                profiles = with_ptz

        idx = min(max(self.profile_index, 0), len(profiles) - 1)
        return str(profiles[idx].get("token"))

    def _ensure(self) -> None:
        if not self._connected:
            self.connect()

    def _call(self, service: str, action: str, body: str) -> ET.Element:
        """Call a service, reconnecting once if the session went stale (camera reboot, clock change)."""
        self._ensure()
        xaddr = {"device": self.device_xaddr, "media": self.media_xaddr, "ptz": self.ptz_xaddr}[service]
        if not xaddr:
            raise OnvifError(f"ONVIF {service} service not available")
        try:
            return self._soap(xaddr, action, body)
        except OnvifError as exc:
            if "transport error" in str(exc):
                raise
            logger.warning("[%s] %s, reconnecting once", self.camera_id, exc)
            self.connect(force=True)
            xaddr = {"device": self.device_xaddr, "media": self.media_xaddr, "ptz": self.ptz_xaddr}[service]
            return self._soap(xaddr or "", action, body)

    # ------------------------------------------------------------------
    # Pose / preset mapping
    # ------------------------------------------------------------------

    def pose_to_token(self, pose_id: int) -> str:
        pose_id = int(pose_id)
        if self.preset_tokens is not None and pose_id in self.cam_poses:
            return self.preset_tokens[self.cam_poses.index(pose_id)]
        return str(pose_id + self.preset_offset)

    def get_device_information(self) -> Dict[str, Optional[str]]:
        body = self._call("device", f"{NS_DEVICE}/GetDeviceInformation", "<tds:GetDeviceInformation/>")
        return {
            k: _text_local(body, k) for k in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId")
        }

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    def _resolve_snapshot_url(self) -> str:
        if self.snapshot_url:
            return self.snapshot_url
        body = self._call(
            "media",
            f"{NS_MEDIA}/GetSnapshotUri",
            f"<trt:GetSnapshotUri><trt:ProfileToken>{self._profile_token_xml()}</trt:ProfileToken>"
            "</trt:GetSnapshotUri>",
        )
        uri = _text_local(body, "Uri")
        if not uri:
            raise OnvifError("Camera returned an empty snapshot URI")
        self.snapshot_url = self._rewrite(uri)
        return self.snapshot_url or uri

    def capture(self, patrol_id: Optional[int] = None, timeout: int = 2) -> Optional[Image.Image]:
        try:
            if patrol_id is not None:
                self.move_camera("ToPos", idx=int(patrol_id))

            url = self._resolve_snapshot_url()
            req_timeout = max(float(timeout), 2.0)
            resp = self._session.get(
                url,
                auth=HTTPDigestAuth(self.username, self.password),
                timeout=req_timeout,
                verify=self.verify_tls,
            )
            if resp.status_code == 401:
                resp = self._session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    timeout=req_timeout,
                    verify=self.verify_tls,
                )
            if resp.status_code == 200 and resp.content:
                return Image.open(BytesIO(resp.content)).convert("RGB")

            logger.error("[%s] Snapshot failed, status %s", self.camera_id, resp.status_code)
            if not self._snapshot_url_forced:
                self.snapshot_url = None  # re-resolve next time
            return None
        except (OnvifError, requests.RequestException, OSError) as exc:
            logger.error("[%s] Capture failed: %s", self.camera_id, exc)
            return None

    # ------------------------------------------------------------------
    # PTZ
    # ------------------------------------------------------------------

    def _profile_token_xml(self) -> str:
        """Escaped profile token. Connects first: request bodies are built before _call runs."""
        self._ensure()
        if not self.profile_token:
            raise OnvifError("No ONVIF profile token resolved")
        return escape(self.profile_token)

    def _profile_xml(self) -> str:
        return f"<tptz:ProfileToken>{self._profile_token_xml()}</tptz:ProfileToken>"

    @staticmethod
    def _speed_to_unit(speed: float) -> float:
        """Map Reolink-style 1..64 speed to ONVIF normalized 0..1 velocity."""
        return round(max(0.0, min(1.0, float(speed) / 64.0)), 3)

    def get_ptz_status(self) -> Dict[str, Any]:
        body = self._call("ptz", f"{NS_PTZ}/GetStatus", f"<tptz:GetStatus>{self._profile_xml()}</tptz:GetStatus>")
        pos = _find_local(body, "Position")
        pan_tilt = _find_local(pos, "PanTilt") if pos is not None else None
        zoom = _find_local(pos, "Zoom") if pos is not None else None
        move = _find_local(body, "MoveStatus")
        return {
            "pan": _float_attr(pan_tilt, "x"),
            "tilt": _float_attr(pan_tilt, "y"),
            "zoom": _float_attr(zoom, "x"),
            "move_status_pan_tilt": _text_local(move, "PanTilt") if move is not None else None,
            "move_status_zoom": _text_local(move, "Zoom") if move is not None else None,
            "utc_time": _text_local(body, "UtcTime"),
        }

    def get_presets(self) -> List[Dict[str, Any]]:
        body = self._call("ptz", f"{NS_PTZ}/GetPresets", f"<tptz:GetPresets>{self._profile_xml()}</tptz:GetPresets>")
        presets: List[Dict[str, Any]] = []
        for p in _iter_local(body, "Preset"):
            token = p.get("token")
            if not token:
                continue
            pt = _find_local(p, "PanTilt")
            zm = _find_local(p, "Zoom")
            presets.append({
                "token": token,
                "name": _text_local(p, "Name"),
                "pan": _float_attr(pt, "x"),
                "tilt": _float_attr(pt, "y"),
                "zoom": _float_attr(zm, "x"),
            })
        self._preset_cache = {p["token"]: p for p in presets}
        return presets

    def get_ptz_preset(self) -> List[Dict[str, Any]]:
        """Route compatible alias, returns presets with the pose they are mapped to (if any)."""
        presets = self.get_presets()
        token_to_pose = {self.pose_to_token(p): p for p in self.cam_poses}
        for p in presets:
            p["pose"] = token_to_pose.get(p["token"])
        return presets

    def goto_preset(self, token: str, wait: bool = True) -> Dict[str, Any]:
        self._call(
            "ptz",
            f"{NS_PTZ}/GotoPreset",
            f"<tptz:GotoPreset>{self._profile_xml()}<tptz:PresetToken>{escape(str(token))}</tptz:PresetToken>"
            "</tptz:GotoPreset>",
        )
        if not wait:
            return {"preset_token": token}
        if token not in self._preset_cache:
            try:
                self.get_presets()
            except OnvifError as exc:
                logger.debug("[%s] Could not refresh presets: %s", self.camera_id, exc)
        status = self.wait_until_idle(target=self._preset_cache.get(token))
        return {"preset_token": token, "status": status}

    def wait_until_idle(
        self,
        target: Optional[Dict[str, Any]] = None,
        timeout_s: Optional[float] = None,
        poll_s: float = 0.25,
        tol: float = 0.01,
    ) -> Dict[str, Any]:
        """
        Block until the PTZ head stops.

        Hikvision firmwares do not always report MoveStatus reliably, so we accept
        either: position within tolerance of the preset target, or MoveStatus IDLE
        plus a stable position over two consecutive polls once `min_settle_s` elapsed
        (avoids returning before the head starts moving).
        """
        min_settle_s = 1.0
        start = time.monotonic()
        deadline = start + (timeout_s if timeout_s is not None else self.move_timeout_s)
        tgt: Dict[str, Any] = target or {}
        has_target = tgt.get("pan") is not None
        last: Optional[Dict[str, Any]] = None
        time.sleep(poll_s)
        while time.monotonic() < deadline:
            st = self.get_ptz_status()

            if has_target and st["pan"] is not None:
                # Zoom left out on purpose: Dahua reports preset zoom and status zoom on different scales
                close = all(
                    tgt.get(k) is None or st.get(k) is None or abs(float(st[k]) - float(tgt[k])) <= tol
                    for k in ("pan", "tilt")
                )
                if close:
                    return st

            stable = last is not None and all(
                st.get(k) is None or last.get(k) is None or abs(float(st[k]) - float(last[k])) <= tol / 10
                for k in ("pan", "tilt", "zoom")
            )
            idle = (st["move_status_pan_tilt"] or "IDLE").upper() == "IDLE"
            if stable and idle and time.monotonic() - start >= min_settle_s:
                if has_target:
                    logger.warning("[%s] PTZ stopped away from preset target %s, status %s", self.camera_id, target, st)
                return st

            last = st
            time.sleep(poll_s)

        raise OnvifError(f"Timeout waiting PTZ to stop, last status {last}")

    def set_ptz_preset(self, idx: Optional[int] = None, name: Optional[str] = None) -> Dict[str, Any]:
        """Save current position as the preset mapped to pose `idx`."""
        if idx is None:
            raise ValueError("idx (pose id) is required to save an ONVIF preset")
        token = self.pose_to_token(int(idx))
        preset_name = name or f"pyronear_pose_{int(idx)}"
        body = self._call(
            "ptz",
            f"{NS_PTZ}/SetPreset",
            f"<tptz:SetPreset>{self._profile_xml()}<tptz:PresetName>{escape(preset_name)}</tptz:PresetName>"
            f"<tptz:PresetToken>{escape(token)}</tptz:PresetToken></tptz:SetPreset>",
        )
        saved = _text_local(body, "PresetToken") or token
        if saved != token:
            logger.warning("[%s] Camera saved preset with token %s instead of %s", self.camera_id, saved, token)
        self._preset_cache.pop(token, None)
        return {"pose": int(idx), "preset_token": saved, "name": preset_name}

    def save_preset(self, idx: int, name: Optional[str] = None) -> Dict[str, Any]:
        return self.set_ptz_preset(idx=idx, name=name)

    def remove_preset(self, idx: int) -> None:
        token = self.pose_to_token(int(idx))
        self._call(
            "ptz",
            f"{NS_PTZ}/RemovePreset",
            f"<tptz:RemovePreset>{self._profile_xml()}<tptz:PresetToken>{escape(token)}</tptz:PresetToken>"
            "</tptz:RemovePreset>",
        )
        self._preset_cache.pop(token, None)

    def _continuous(self, pan: float, tilt: float, zoom: float) -> None:
        velocity = ""
        if pan or tilt:
            velocity += f'<tt:PanTilt x="{pan}" y="{tilt}"/>'
        if zoom:
            velocity += f'<tt:Zoom x="{zoom}"/>'
        self._call(
            "ptz",
            f"{NS_PTZ}/ContinuousMove",
            f"<tptz:ContinuousMove>{self._profile_xml()}<tptz:Velocity>{velocity}</tptz:Velocity>"
            "</tptz:ContinuousMove>",
        )

    def stop(self) -> None:
        self._call(
            "ptz",
            f"{NS_PTZ}/Stop",
            f"<tptz:Stop>{self._profile_xml()}<tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>",
        )

    def absolute_move(self, pan: Optional[float] = None, tilt: Optional[float] = None, zoom: Optional[float] = None):
        """Move in ONVIF normalized space (pan/tilt -1..1, zoom 0..1). Missing axes keep current value."""
        if pan is None or tilt is None or zoom is None:
            st = self.get_ptz_status()
            pan = st["pan"] if pan is None else pan
            tilt = st["tilt"] if tilt is None else tilt
            zoom = st["zoom"] if zoom is None else zoom
        position = ""
        if pan is not None and tilt is not None:
            position += f'<tt:PanTilt x="{float(pan)}" y="{float(tilt)}"/>'
        if zoom is not None:
            position += f'<tt:Zoom x="{float(zoom)}"/>'
        self._call(
            "ptz",
            f"{NS_PTZ}/AbsoluteMove",
            f"<tptz:AbsoluteMove>{self._profile_xml()}<tptz:Position>{position}</tptz:Position></tptz:AbsoluteMove>",
        )

    def move_camera(self, operation: str, speed: int = 20, idx: int = 0):
        """
        Supported operations (same vocabulary as the other adapters)
          ToPos     idx is the pyronear pose id, mapped to an ONVIF preset token; blocks until the head stops
          Stop
          Left, Right, Up, Down, UpLeft, UpRight, DownLeft, DownRight, ZoomIn, ZoomOut
                    continuous move at speed (1..64 mapped to ONVIF 0..1) until Stop
        """
        if self.cam_type == "static":
            return None

        op = operation.strip()
        with self._lock:
            if op == "ToPos":
                token = self.pose_to_token(int(idx))
                logger.info("[%s] GotoPreset pose=%s token=%s", self.camera_id, idx, token)
                return self.goto_preset(token)

            if op == "Stop":
                self.stop()
                return None

            v = self._speed_to_unit(speed)
            vectors = {
                "Left": (-v, 0.0, 0.0),
                "Right": (v, 0.0, 0.0),
                "Up": (0.0, v, 0.0),
                "Down": (0.0, -v, 0.0),
                "UpLeft": (-v, v, 0.0),
                "UpRight": (v, v, 0.0),
                "DownLeft": (-v, -v, 0.0),
                "DownRight": (v, -v, 0.0),
                "ZoomIn": (0.0, 0.0, v),
                "ZoomOut": (0.0, 0.0, -v),
            }
            if op not in vectors:
                raise ValueError(f"Unsupported PTZ operation: {operation}")
            self._continuous(*vectors[op])
            return None

    def start_zoom_focus(self, position: int) -> Optional[Dict[str, float]]:
        """Route /zoom uses 0..64, mapped to ONVIF normalized zoom 0..1, pan/tilt unchanged."""
        if self.cam_type == "static":
            return None
        z = round(max(0.0, min(1.0, float(position) / 64.0)), 4)
        self.absolute_move(zoom=z)
        return {"zoom": z}

    def reboot_camera(self) -> bool:
        try:
            self._call("device", f"{NS_DEVICE}/SystemReboot", "<tds:SystemReboot/>")
            self._connected = False
            return True
        except OnvifError as exc:
            logger.error("[%s] Reboot failed: %s", self.camera_id, exc)
            return False
