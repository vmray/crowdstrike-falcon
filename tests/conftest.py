"""Shared fixtures for the connector test suite."""

import pytest
from unittest.mock import MagicMock, patch

from lib.Sample import Sample
from lib.CrowdStrike import CrowdStrike, ConnectorDetect, ConnectorQuarantine
from lib.VMRay import VMRay
from config.general_conf import VERDICT
from config.crowdstrike_conf import CrowdStrikeConfig, DATA_SOURCE


SHA256 = "a" * 64


@pytest.fixture
def sample():
    return Sample(SHA256)


@pytest.fixture
def cs(mocker):
    """CrowdStrike instance with _authenticate bypassed and API clients mocked."""
    mocker.patch.object(CrowdStrike, "_authenticate")
    instance = CrowdStrike()
    instance.alerts_api = MagicMock()
    instance.quarantine_api = MagicMock()
    instance.sample_api = MagicMock()
    instance.ioc_api = MagicMock()
    return instance


@pytest.fixture
def vmray_instance(mocker):
    """VMRay instance with authenticate/healthcheck bypassed and api client mocked."""
    mocker.patch.object(VMRay, "authenticate")
    mocker.patch.object(VMRay, "healthcheck")
    instance = VMRay()
    instance.api = MagicMock()
    return instance


@pytest.fixture
def connector_detect():
    return ConnectorDetect(
        composite_id="comp1",
        timestamp="2024-01-01T00:00:00Z",
        host_id="host1",
        included_sha256=SHA256,
        os_version="Windows 10",
        device_id="dev1",
        file_path="/malware/file.exe",
    )


@pytest.fixture
def connector_quarantine():
    return ConnectorQuarantine(
        quarantine_id="q1",
        timestamp="2024-01-01T00:00:00Z",
        sha256_hash=SHA256,
        hostname="workstation1",
        filename="malware.exe",
        quarantine_host_id="aid1",
    )


def make_quarantine_query_response(ids, total=None):
    """Build a mock query_quarantine_files response."""
    return {
        "body": {
            "resources": ids,
            "meta": {"pagination": {"total": total if total is not None else len(ids)}},
            "errors": None,
        }
    }


def make_quarantine_files_response(quarantines):
    """Build a mock get_quarantine_files response."""
    return {
        "body": {
            "resources": quarantines,
            "errors": None,
        }
    }


def make_alerts_response(resources, after=None):
    """Build a mock get_alerts_combined response."""
    return {
        "body": {
            "resources": resources,
            "meta": {"pagination": {"after": after}},
            "errors": None,
        }
    }


def make_error_response(message="Something went wrong"):
    return {
        "body": {
            "errors": [{"message": message}],
            "resources": None,
        }
    }


def raw_quarantine_record(sha256=SHA256, qid="q1", date="2024-01-01T00:00:00Z"):
    return {
        "id": qid,
        "sha256": sha256,
        "date_created": date,
        "hostname": "workstation1",
        "aid": "aid1",
        "paths": [{"filename": "malware.exe"}],
    }


def raw_alert_record(sha256=SHA256, composite_id="c1"):
    return {
        "composite_id": composite_id,
        "sha256": sha256,
        "created_timestamp": "2024-01-01T00:00:00Z",
        "filepath": "/malware/file.exe",
        "device": {"device_id": "dev1", "os_version": "Windows 10"},
    }
