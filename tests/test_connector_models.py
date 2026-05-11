"""Tests for ConnectorDetect and ConnectorQuarantine DTOs."""

from datetime import datetime

import pytest

from lib.CrowdStrike import ConnectorDetect, ConnectorQuarantine

SHA256 = "c" * 64


class TestConnectorDetect:
    def _make(self, **kwargs):
        defaults = dict(
            composite_id="comp1",
            timestamp=datetime(2024, 1, 1),
            host_id="host1",
            included_sha256=SHA256,
            os_version="Windows 10",
            device_id="dev1",
            file_path="/malware/file.exe",
        )
        defaults.update(kwargs)
        return ConnectorDetect(**defaults)

    def test_all_fields_stored(self):
        cd = self._make()
        assert cd.composite_id == "comp1"
        assert cd.timestamp == datetime(2024, 1, 1)
        assert cd.host_id == "host1"
        assert cd.included_sha256 == SHA256
        assert cd.os_version == "Windows 10"
        assert cd.device_id == "dev1"
        assert cd.file_path == "/malware/file.exe"

    def test_str_contains_composite_id(self):
        cd = self._make()
        assert "comp1" in str(cd)

    def test_str_contains_sha256(self):
        cd = self._make()
        assert SHA256 in str(cd)

    def test_str_contains_device_id(self):
        cd = self._make()
        assert "dev1" in str(cd)

    def test_str_is_string(self):
        cd = self._make()
        assert isinstance(str(cd), str)

    def test_empty_strings_allowed(self):
        cd = ConnectorDetect("", None, "", "", "", "", "")
        assert cd.composite_id == ""
        assert cd.included_sha256 == ""


class TestConnectorQuarantine:
    def _make(self, **kwargs):
        defaults = dict(
            quarantine_id="q1",
            timestamp=datetime(2024, 1, 1),
            sha256_hash=SHA256,
            hostname="workstation1",
            filename="malware.exe",
            quarantine_host_id="aid1",
        )
        defaults.update(kwargs)
        return ConnectorQuarantine(**defaults)

    def test_all_fields_stored(self):
        cq = self._make()
        assert cq.quarantine_id == "q1"
        assert cq.timestamp == datetime(2024, 1, 1)
        assert cq.sha256_hash == SHA256
        assert cq.hostname == "workstation1"
        assert cq.filename == "malware.exe"
        assert cq.quarantine_host_id == "aid1"

    def test_str_contains_quarantine_id(self):
        cq = self._make()
        assert "q1" in str(cq)

    def test_str_contains_sha256(self):
        cq = self._make()
        assert SHA256 in str(cq)

    def test_str_contains_filename(self):
        cq = self._make()
        assert "malware.exe" in str(cq)

    def test_str_contains_hostname(self):
        cq = self._make()
        assert "workstation1" in str(cq)

    def test_str_is_string(self):
        cq = self._make()
        assert isinstance(str(cq), str)
