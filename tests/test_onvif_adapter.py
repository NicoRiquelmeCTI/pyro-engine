# ruff: noqa: S105, S314, S324, S405, ARG002, ANN204
# Fake ONVIF device: parses our own SOAP output and recomputes the WS-Security SHA1 digest on purpose.
import base64
import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pyro_camera_api"))

from pyro_camera_api.camera.adapters import onvif as onvif_mod
from pyro_camera_api.camera.adapters.onvif import OnvifCamera, OnvifError

USER, PWD = "onvif_user", "s3cr3t<&>"


class FakeResp:
    def __init__(self, status_code=200, content=b""):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", "replace")


def soap(body):
    return (
        '<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
        'xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">'
        f"<env:Body>{body}</env:Body></env:Envelope>"
    ).encode()


def fault(reason):
    return soap(
        "<env:Fault><env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>ter:NotAuthorized</env:Value>"
        f"</env:Subcode></env:Code><env:Reason><env:Text>{reason}</env:Text></env:Reason></env:Fault>"
    )


class FakeHikvision:
    """Minimal ONVIF device: Hikvision-like XAddrs with an unreachable host, presets 1..4."""

    def __init__(self):
        self.pan, self.tilt, self.zoom = 0.0, 0.0, 0.0
        self.presets = {str(i): (round(-0.75 + 0.5 * (i - 1), 2), 0.1, 0.0) for i in range(1, 5)}
        self.calls = []
        self.posts = []
        self.reject_auth_once = False
        self.snapshot_status = 200

    def _check_digest(self, xml):
        root = ET.fromstring(xml)
        ns = {"w": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"}
        tok = root.find(".//w:UsernameToken", ns)
        assert tok.find("w:Username", ns).text == USER
        nonce = base64.b64decode(tok.find("w:Nonce", ns).text)
        created = tok.find("{*}Created").text
        expected = base64.b64encode(hashlib.sha1(nonce + created.encode() + PWD.encode()).digest()).decode()
        assert tok.find("w:Password", ns).text == expected

    def post(self, url, data, headers, timeout, verify):
        action = re.search(r'action="[^"]*/(\w+)"', headers["Content-Type"]).group(1)
        self.calls.append(action)
        self.posts.append((url, action, data.decode()))
        if action != "GetSystemDateAndTime":
            self._check_digest(data)
            if self.reject_auth_once:
                self.reject_auth_once = False
                return FakeResp(400, fault("Sender not authorized"))
        token_match = re.search(r"<\w+:ProfileToken>(.*?)</\w+:ProfileToken>", data.decode())
        if token_match and token_match.group(1) != "Profile_1":
            # Dahua behaviour: empty or unknown token is rejected
            return FakeResp(200, fault("Profile token does not exist"))
        body = data.decode()

        if action == "GetSystemDateAndTime":
            return FakeResp(
                content=soap(
                    "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:UTCDateTime>"
                    "<tt:Date><tt:Year>2026</tt:Year><tt:Month>11</tt:Month><tt:Day>9</tt:Day></tt:Date>"
                    "<tt:Time><tt:Hour>12</tt:Hour><tt:Minute>0</tt:Minute><tt:Second>0</tt:Second></tt:Time>"
                    "</tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>"
                )
            )
        if action == "GetCapabilities":
            return FakeResp(
                content=soap(
                    "<tds:GetCapabilitiesResponse><tds:Capabilities>"
                    "<tt:Media><tt:XAddr>http://10.0.0.99/onvif/Media</tt:XAddr></tt:Media>"
                    "<tt:PTZ><tt:XAddr>http://10.0.0.99/onvif/PTZ</tt:XAddr></tt:PTZ>"
                    "</tds:Capabilities></tds:GetCapabilitiesResponse>"
                )
            )
        if action == "GetProfiles":
            return FakeResp(
                content=soap(
                    '<trt:GetProfilesResponse><trt:Profiles token="Profile_1"><tt:Name>main</tt:Name>'
                    '<tt:PTZConfiguration token="PTZ1"/></trt:Profiles>'
                    '<trt:Profiles token="Profile_2"><tt:Name>sub</tt:Name></trt:Profiles></trt:GetProfilesResponse>'
                )
            )
        if action == "GetSnapshotUri":
            return FakeResp(
                content=soap(
                    "<trt:GetSnapshotUriResponse><trt:MediaUri>"
                    "<tt:Uri>http://10.0.0.99/onvif-http/snapshot?Profile_1</tt:Uri>"
                    "</trt:MediaUri></trt:GetSnapshotUriResponse>"
                )
            )
        if action == "GetPresets":
            items = "".join(
                f'<tptz:Preset token="{t}"><tt:Name>p{t}</tt:Name><tt:PTZPosition>'
                f'<tt:PanTilt x="{p}" y="{ti}"/><tt:Zoom x="{z}"/></tt:PTZPosition></tptz:Preset>'
                for t, (p, ti, z) in self.presets.items()
            )
            return FakeResp(content=soap(f"<tptz:GetPresetsResponse>{items}</tptz:GetPresetsResponse>"))
        if action == "GotoPreset":
            token = re.search(r"<tptz:PresetToken>(.*?)</tptz:PresetToken>", body).group(1)
            if token not in self.presets:
                return FakeResp(400, fault("No such PTZ preset"))
            self.pan, self.tilt, self.zoom = self.presets[token]
            return FakeResp(content=soap("<tptz:GotoPresetResponse/>"))
        if action == "SetPreset":
            token = re.search(r"<tptz:PresetToken>(.*?)</tptz:PresetToken>", body).group(1)
            self.presets[token] = (self.pan, self.tilt, self.zoom)
            return FakeResp(
                content=soap(
                    f"<tptz:SetPresetResponse><tptz:PresetToken>{token}</tptz:PresetToken></tptz:SetPresetResponse>"
                )
            )
        if action == "GetStatus":
            return FakeResp(
                content=soap(
                    "<tptz:GetStatusResponse><tptz:PTZStatus><tt:Position>"
                    f'<tt:PanTilt x="{self.pan}" y="{self.tilt}"/><tt:Zoom x="{self.zoom}"/></tt:Position>'
                    "<tt:MoveStatus><tt:PanTilt>IDLE</tt:PanTilt><tt:Zoom>IDLE</tt:Zoom></tt:MoveStatus>"
                    "</tptz:PTZStatus></tptz:GetStatusResponse>"
                )
            )
        if action == "AbsoluteMove":
            m = re.search(r'<tt:Zoom x="([\d.]+)"', body)
            if m:
                self.zoom = float(m.group(1))
            return FakeResp(content=soap("<tptz:AbsoluteMoveResponse/>"))
        if action in ("ContinuousMove", "Stop", "RemovePreset", "SystemReboot"):
            return FakeResp(content=soap(f"<tptz:{action}Response/>"))
        return FakeResp(400, fault(f"unsupported {action}"))

    def get(self, url, auth, timeout, verify):
        self.calls.append(("GET", url, type(auth).__name__))
        buf = BytesIO()
        Image.new("RGB", (8, 6), (200, 10, 10)).save(buf, format="JPEG")
        return FakeResp(self.snapshot_status, buf.getvalue() if self.snapshot_status == 200 else b"")


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(onvif_mod.time, "sleep", lambda *_: None)


@pytest.fixture
def cam(no_sleep):
    c = OnvifCamera("192.168.1.64", "192.168.1.64", USER, PWD, cam_poses=[0, 1, 2, 3], cam_azimuths=[0, 90, 180, 270])
    c._session = FakeHikvision()
    return c


def test_lazy_connect_no_network_at_init(no_sleep):
    c = OnvifCamera("x", "192.168.99.99", USER, PWD)
    assert not c._connected
    assert c.media_xaddr is None


def test_connect_rewrites_xaddrs_and_picks_ptz_profile(cam):
    cam.connect()
    assert cam.media_xaddr == "http://192.168.1.64:80/onvif/Media"
    assert cam.ptz_xaddr == "http://192.168.1.64:80/onvif/PTZ"
    assert cam.profile_token == "Profile_1"


def test_default_pose_mapping_hikvision_offset(cam):
    assert [cam.pose_to_token(p) for p in [0, 1, 2, 3]] == ["1", "2", "3", "4"]


def test_explicit_preset_tokens():
    c = OnvifCamera("x", "1.2.3.4", USER, PWD, cam_poses=[0, 1, 2, 3], preset_tokens=[10, 11, 12, 13])
    assert c.pose_to_token(2) == "12"
    with pytest.raises(ValueError, match="same length"):
        OnvifCamera("x", "1.2.3.4", USER, PWD, cam_poses=[0, 1], preset_tokens=["1"])


@pytest.mark.parametrize("pose", [0, 1, 2, 3])
def test_to_pos_moves_to_each_of_the_4_presets(cam, pose):
    res = cam.move_camera("ToPos", idx=pose)
    expected = cam._session.presets[str(pose + 1)]
    assert res["preset_token"] == str(pose + 1)
    assert (res["status"]["pan"], res["status"]["tilt"]) == expected[:2]
    assert "GotoPreset" in cam._session.calls


def test_goto_unknown_preset_raises_fault(cam):
    with pytest.raises(OnvifError, match="No such PTZ preset"):
        cam.move_camera("ToPos", idx=50)


def test_set_preset_saves_pose_token(cam):
    res = cam.set_ptz_preset(idx=3)
    assert res == {"pose": 3, "preset_token": "4", "name": "pyronear_pose_3"}


def test_get_ptz_preset_maps_pose(cam):
    presets = cam.get_ptz_preset()
    assert {p["token"]: p["pose"] for p in presets} == {"1": 0, "2": 1, "3": 2, "4": 3}


def test_continuous_and_stop(cam):
    cam.move_camera("Left", speed=32)
    _, action, body = cam._session.posts[-1]
    assert action == "ContinuousMove"
    assert 'x="-0.5" y="0.0"' in body
    cam.move_camera("Stop")
    assert cam._session.posts[-1][1] == "Stop"
    with pytest.raises(ValueError, match="Unsupported PTZ operation"):
        cam.move_camera("Spin")


def test_static_camera_ignores_ptz(no_sleep):
    c = OnvifCamera("x", "1.2.3.4", USER, PWD, cam_type="static")
    c._session = FakeHikvision()
    assert c.move_camera("ToPos", idx=1) is None
    assert c._session.calls == []


def test_capture_uses_snapshot_uri_with_digest(cam):
    img = cam.capture()
    assert isinstance(img, Image.Image)
    assert img.size == (8, 6)
    get_call = next(c for c in cam._session.calls if isinstance(c, tuple))
    assert get_call == ("GET", "http://192.168.1.64:80/onvif-http/snapshot?Profile_1", "HTTPDigestAuth")


def test_capture_with_patrol_id_moves_first(cam):
    assert cam.capture(patrol_id=2) is not None
    assert cam._session.calls.index("GotoPreset") < next(
        i for i, c in enumerate(cam._session.calls) if isinstance(c, tuple)
    )


def test_capture_failure_returns_none(cam):
    cam._session.snapshot_status = 500
    assert cam.capture() is None


def test_reconnects_once_on_fault(cam):
    cam.connect()
    cam._session.reject_auth_once = True
    cam.move_camera("ToPos", idx=0)
    assert cam._session.calls.count("GetCapabilities") == 2


def test_zoom_maps_0_64(cam):
    assert cam.start_zoom_focus(32) == {"zoom": 0.5}
    assert cam._session.zoom == 0.5


def test_password_is_xml_escaped_in_username_only(cam):
    cam.connect()
    body = cam._session.posts[-1][2]
    assert PWD not in body  # only the digest travels


@pytest.mark.parametrize("adapter", ["onvif", "hikvision-onvif", "ONVIF"])
def test_registry_routes_onvif_adapters(adapter):
    registry = pytest.importorskip("pyro_camera_api.camera.registry")
    conf = {"adapter": adapter, "type": "ptz", "poses": [0, 1, 2, 3], "azimuths": [0, 90, 180, 270], "username": USER}
    cam = registry.build_camera_object("192.168.1.64", conf)
    assert isinstance(cam, OnvifCamera)
    assert cam.pose_to_token(3) == "4"
    assert not cam._connected
