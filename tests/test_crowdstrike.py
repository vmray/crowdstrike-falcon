"""Tests for the CrowdStrike wrapper class."""

import hashlib
import pathlib
from datetime import datetime
from unittest.mock import MagicMock, call, patch

import pytest

from lib.CrowdStrike import CrowdStrike, ConnectorDetect, ConnectorQuarantine
from lib.Sample import Sample
from config.general_conf import VERDICT
from config.constants import (
    CS_DATETIME_FORMAT,
    IOC_ACTION_PREVENT,
    IOC_ACTION_DETECT,
    IOC_PLATFORMS,
    IOC_TAGS,
    IOC_SEVERITY,
    MAX_COMMENT_LENGTH,
)
from tests.conftest import (
    SHA256,
    make_quarantine_query_response,
    make_quarantine_files_response,
    make_alerts_response,
    make_error_response,
    raw_quarantine_record,
    raw_alert_record,
)


# ---------------------------------------------------------------------------
# _authenticate
# ---------------------------------------------------------------------------

class TestAuthenticate:
    def test_success_sets_all_api_clients(self, mocker):
        mock_alerts = MagicMock()
        mock_alerts.authenticated.return_value = True
        mock_quar = MagicMock()
        mock_quar.authenticated.return_value = True
        mock_sample = MagicMock()
        mock_sample.authenticated.return_value = True
        mock_ioc = MagicMock()
        mock_ioc.authenticated.return_value = True

        mocker.patch("lib.CrowdStrike.Alerts", return_value=mock_alerts)
        mocker.patch("lib.CrowdStrike.Quarantine", return_value=mock_quar)
        mocker.patch("lib.CrowdStrike.SampleUploads", return_value=mock_sample)
        mocker.patch("lib.CrowdStrike.IOC", return_value=mock_ioc)

        cs = CrowdStrike()

        assert cs.alerts_api is mock_alerts
        assert cs.quarantine_api is mock_quar
        assert cs.sample_api is mock_sample
        assert cs.ioc_api is mock_ioc

    def test_alerts_auth_failure_raises(self, mocker):
        mock_alerts = MagicMock()
        mock_alerts.authenticated.return_value = False

        mocker.patch("lib.CrowdStrike.Alerts", return_value=mock_alerts)
        mocker.patch("lib.CrowdStrike.Quarantine")
        mocker.patch("lib.CrowdStrike.SampleUploads")
        mocker.patch("lib.CrowdStrike.IOC")

        with pytest.raises(Exception, match="Alerts API authentication failed"):
            CrowdStrike()

    def test_quarantine_auth_failure_raises(self, mocker):
        mock_alerts = MagicMock()
        mock_alerts.authenticated.return_value = True
        mock_quar = MagicMock()
        mock_quar.authenticated.return_value = False

        mocker.patch("lib.CrowdStrike.Alerts", return_value=mock_alerts)
        mocker.patch("lib.CrowdStrike.Quarantine", return_value=mock_quar)
        mocker.patch("lib.CrowdStrike.SampleUploads")
        mocker.patch("lib.CrowdStrike.IOC")

        with pytest.raises(Exception, match="Quarantine API authentication failed"):
            CrowdStrike()

    def test_sample_uploads_auth_failure_raises(self, mocker):
        mock_alerts = MagicMock()
        mock_alerts.authenticated.return_value = True
        mock_quar = MagicMock()
        mock_quar.authenticated.return_value = True
        mock_sample = MagicMock()
        mock_sample.authenticated.return_value = False

        mocker.patch("lib.CrowdStrike.Alerts", return_value=mock_alerts)
        mocker.patch("lib.CrowdStrike.Quarantine", return_value=mock_quar)
        mocker.patch("lib.CrowdStrike.SampleUploads", return_value=mock_sample)
        mocker.patch("lib.CrowdStrike.IOC")

        with pytest.raises(Exception, match="SampleUploads API authentication failed"):
            CrowdStrike()

    def test_ioc_auth_failure_raises(self, mocker):
        mock_alerts = MagicMock()
        mock_alerts.authenticated.return_value = True
        mock_quar = MagicMock()
        mock_quar.authenticated.return_value = True
        mock_sample = MagicMock()
        mock_sample.authenticated.return_value = True
        mock_ioc = MagicMock()
        mock_ioc.authenticated.return_value = False

        mocker.patch("lib.CrowdStrike.Alerts", return_value=mock_alerts)
        mocker.patch("lib.CrowdStrike.Quarantine", return_value=mock_quar)
        mocker.patch("lib.CrowdStrike.SampleUploads", return_value=mock_sample)
        mocker.patch("lib.CrowdStrike.IOC", return_value=mock_ioc)

        with pytest.raises(Exception, match="IOC API authentication failed"):
            CrowdStrike()


# ---------------------------------------------------------------------------
# _extract_error_msg
# ---------------------------------------------------------------------------

class TestExtractErrorMsg:
    def test_errors_list_returns_first_message(self):
        response = {"body": {"errors": [{"message": "not authorized"}]}}
        assert CrowdStrike._extract_error_msg(response) == "not authorized"

    def test_errors_list_entry_without_message_returns_str_of_entry(self):
        response = {"body": {"errors": [{"code": 401}]}}
        result = CrowdStrike._extract_error_msg(response)
        assert "401" in result

    def test_message_field_fallback(self):
        response = {"body": {"errors": [], "message": "forbidden"}}
        assert CrowdStrike._extract_error_msg(response) == "forbidden"

    def test_no_errors_no_message_returns_str_of_response(self):
        response = {"body": {"errors": [], "message": None}}
        result = CrowdStrike._extract_error_msg(response)
        assert isinstance(result, str)

    def test_non_dict_response_returns_str(self):
        result = CrowdStrike._extract_error_msg("raw error string")
        assert isinstance(result, str)

    def test_missing_body_returns_str(self):
        result = CrowdStrike._extract_error_msg({})
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# get_quarantines
# ---------------------------------------------------------------------------

class TestGetQuarantines:
    def test_returns_empty_list_when_no_ids(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response([], total=0)
        result = cs.get_quarantines()
        assert result == []

    def test_returns_quarantine_objects(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response(["q1"])
        cs.quarantine_api.get_quarantine_files.return_value = make_quarantine_files_response(
            [raw_quarantine_record()]
        )
        result = cs.get_quarantines()
        assert len(result) == 1
        assert isinstance(result[0], ConnectorQuarantine)
        assert result[0].quarantine_id == "q1"
        assert result[0].sha256_hash == SHA256

    def test_parses_filename_from_paths(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response(["q1"])
        record = raw_quarantine_record()
        cs.quarantine_api.get_quarantine_files.return_value = make_quarantine_files_response([record])
        result = cs.get_quarantines()
        assert result[0].filename == "malware.exe"

    def test_empty_paths_gives_empty_filename(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response(["q1"])
        record = raw_quarantine_record()
        record["paths"] = []
        cs.quarantine_api.get_quarantine_files.return_value = make_quarantine_files_response([record])
        result = cs.get_quarantines()
        assert result[0].filename == ""

    def test_pagination_fetches_all_ids(self, cs):
        # Two query pages, IDs from both pages, all fit in a single batch fetch
        first_page = make_quarantine_query_response(["q1", "q2"], total=3)
        second_page = make_quarantine_query_response(["q3"], total=3)
        cs.quarantine_api.query_quarantine_files.side_effect = [first_page, second_page]

        record1 = raw_quarantine_record(qid="q1", sha256="a" * 64)
        record2 = raw_quarantine_record(qid="q2", sha256="b" * 64)
        record3 = raw_quarantine_record(qid="q3", sha256="c" * 64)
        # All 3 IDs land in a single batch (<100), so get_quarantine_files is called once
        cs.quarantine_api.get_quarantine_files.return_value = make_quarantine_files_response(
            [record1, record2, record3]
        )

        result = cs.get_quarantines()
        assert len(result) == 3
        ids = {q.quarantine_id for q in result}
        assert ids == {"q1", "q2", "q3"}

    def test_query_api_error_raises(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_error_response("access denied")
        with pytest.raises(Exception, match="access denied"):
            cs.get_quarantines()

    def test_get_files_api_error_raises(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response(["q1"])
        cs.quarantine_api.get_quarantine_files.return_value = make_error_response("fetch failed")
        with pytest.raises(Exception, match="fetch failed"):
            cs.get_quarantines()

    def test_parses_date_created(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response(["q1"])
        cs.quarantine_api.get_quarantine_files.return_value = make_quarantine_files_response(
            [raw_quarantine_record(date="2024-06-15T12:30:00Z")]
        )
        result = cs.get_quarantines()
        assert result[0].timestamp == datetime(2024, 6, 15, 12, 30, 0)

    def test_bad_date_format_skips_record_but_keeps_others(self, cs):
        cs.quarantine_api.query_quarantine_files.return_value = make_quarantine_query_response(["q1", "q2"])
        record_good = raw_quarantine_record(qid="q1", date="2024-06-15T12:30:00Z")
        record_bad = raw_quarantine_record(qid="q2", date="not-a-date")
        cs.quarantine_api.get_quarantine_files.return_value = make_quarantine_files_response(
            [record_good, record_bad]
        )
        result = cs.get_quarantines()
        assert len(result) == 1
        assert result[0].quarantine_id == "q1"


# ---------------------------------------------------------------------------
# extract_hash_from_quarantines
# ---------------------------------------------------------------------------

class TestExtractHashFromQuarantines:
    def test_returns_hashes(self, cs, connector_quarantine):
        result = cs.extract_hash_from_quarantines([connector_quarantine])
        assert result == [SHA256]

    def test_empty_list(self, cs):
        assert cs.extract_hash_from_quarantines([]) == []

    def test_preserves_order(self, cs):
        q1 = ConnectorQuarantine("q1", None, "a" * 64, "h", "f", "aid")
        q2 = ConnectorQuarantine("q2", None, "b" * 64, "h", "f", "aid")
        q3 = ConnectorQuarantine("q3", None, "c" * 64, "h", "f", "aid")
        result = cs.extract_hash_from_quarantines([q1, q2, q3])
        assert result == ["a" * 64, "b" * 64, "c" * 64]


# ---------------------------------------------------------------------------
# get_alerts
# ---------------------------------------------------------------------------

class TestGetAlerts:
    def test_returns_empty_list_when_no_resources(self, cs):
        cs.alerts_api.get_alerts_combined.return_value = make_alerts_response([], after=None)
        result = cs.get_alerts()
        assert result == []

    def test_returns_alert_objects(self, cs):
        cs.alerts_api.get_alerts_combined.return_value = make_alerts_response(
            [raw_alert_record()], after=None
        )
        result = cs.get_alerts()
        assert len(result) == 1
        assert isinstance(result[0], ConnectorDetect)
        assert result[0].composite_id == "c1"
        assert result[0].included_sha256 == SHA256

    def test_skips_alert_without_sha256(self, cs):
        record = raw_alert_record()
        del record["sha256"]
        cs.alerts_api.get_alerts_combined.return_value = make_alerts_response([record], after=None)
        result = cs.get_alerts()
        assert result == []

    def test_skips_alert_with_empty_sha256(self, cs):
        record = raw_alert_record()
        record["sha256"] = ""
        cs.alerts_api.get_alerts_combined.return_value = make_alerts_response([record], after=None)
        result = cs.get_alerts()
        assert result == []

    def test_skips_alert_without_composite_id(self, cs):
        record = raw_alert_record()
        del record["composite_id"]
        cs.alerts_api.get_alerts_combined.return_value = make_alerts_response([record], after=None)
        result = cs.get_alerts()
        assert result == []

    def test_cursor_pagination(self, cs):
        page1 = make_alerts_response([raw_alert_record(composite_id="c1")], after="cursor1")
        page2 = make_alerts_response([raw_alert_record(composite_id="c2")], after=None)
        cs.alerts_api.get_alerts_combined.side_effect = [page1, page2]
        result = cs.get_alerts()
        assert len(result) == 2
        assert {a.composite_id for a in result} == {"c1", "c2"}

    def test_api_error_raises(self, cs):
        cs.alerts_api.get_alerts_combined.return_value = make_error_response("rate limited")
        with pytest.raises(Exception, match="rate limited"):
            cs.get_alerts()

    def test_missing_device_fields_default_to_empty(self, cs):
        record = raw_alert_record()
        record["device"] = {}
        cs.alerts_api.get_alerts_combined.return_value = make_alerts_response([record], after=None)
        result = cs.get_alerts()
        assert result[0].host_id == ""
        assert result[0].os_version == ""


# ---------------------------------------------------------------------------
# extract_hashes_from_alerts
# ---------------------------------------------------------------------------

class TestExtractHashesFromAlerts:
    def test_returns_hashes(self, cs, connector_detect):
        result = cs.extract_hashes_from_alerts([connector_detect])
        assert result == [SHA256]

    def test_empty_list(self, cs):
        assert cs.extract_hashes_from_alerts([]) == []

    def test_preserves_order(self, cs):
        d1 = ConnectorDetect("c1", None, "", "a" * 64, "", "", "")
        d2 = ConnectorDetect("c2", None, "", "b" * 64, "", "", "")
        result = cs.extract_hashes_from_alerts([d1, d2])
        assert result == ["a" * 64, "b" * 64]


# ---------------------------------------------------------------------------
# download_malware_sample
# ---------------------------------------------------------------------------

class TestDownloadMalwareSample:
    def test_api_returns_dict_sets_not_downloaded(self, cs, tmp_path, mocker):
        mocker.patch.object(cs.config, "DOWNLOAD_DIR_PATH", tmp_path)
        cs.sample_api.get_sample.return_value = {"body": {"errors": [{"message": "not found"}]}}
        sample = Sample(SHA256)
        cs.download_malware_sample(sample)
        assert sample.downloaded_successfully is False

    def test_api_exception_sets_not_downloaded(self, cs, tmp_path, mocker):
        mocker.patch.object(cs.config, "DOWNLOAD_DIR_PATH", tmp_path)
        cs.sample_api.get_sample.side_effect = Exception("connection error")
        sample = Sample(SHA256)
        cs.download_malware_sample(sample)
        assert sample.downloaded_successfully is False

    def test_file_write_failure_sets_not_downloaded(self, cs, tmp_path, mocker):
        mocker.patch.object(cs.config, "DOWNLOAD_DIR_PATH", tmp_path)
        cs.sample_api.get_sample.return_value = b"fake zip bytes"
        mocker.patch("builtins.open", side_effect=IOError("disk full"))
        sample = Sample(SHA256)
        cs.download_malware_sample(sample)
        assert sample.downloaded_successfully is False

    def test_zip_extraction_failure_sets_not_downloaded(self, cs, tmp_path, mocker):
        mocker.patch.object(cs.config, "DOWNLOAD_DIR_PATH", tmp_path)
        cs.sample_api.get_sample.return_value = b"fake zip bytes"
        mocker.patch("lib.CrowdStrike.zipfile.ZipFile", side_effect=Exception("bad zip"))
        sample = Sample(SHA256)
        cs.download_malware_sample(sample)
        assert sample.downloaded_successfully is False

    def test_integrity_check_failure_sets_not_downloaded(self, cs, tmp_path, mocker):
        mocker.patch.object(cs.config, "DOWNLOAD_DIR_PATH", tmp_path)
        cs.sample_api.get_sample.return_value = b"fake zip bytes"

        mock_zip = MagicMock()
        mock_zip_ctx = MagicMock()
        mock_zip_ctx.__enter__ = MagicMock(return_value=mock_zip)
        mock_zip_ctx.__exit__ = MagicMock(return_value=False)
        mocker.patch("lib.CrowdStrike.zipfile.ZipFile", return_value=mock_zip_ctx)
        mocker.patch.object(cs, "_check_file_integrity", return_value=False)

        sample = Sample(SHA256)
        cs.download_malware_sample(sample)
        assert sample.downloaded_successfully is False

    def test_success_sets_downloaded_and_paths(self, cs, tmp_path, mocker):
        mocker.patch.object(cs.config, "DOWNLOAD_DIR_PATH", tmp_path)
        cs.sample_api.get_sample.return_value = b"fake zip bytes"

        mock_zip = MagicMock()
        mock_zip_ctx = MagicMock()
        mock_zip_ctx.__enter__ = MagicMock(return_value=mock_zip)
        mock_zip_ctx.__exit__ = MagicMock(return_value=False)
        mocker.patch("lib.CrowdStrike.zipfile.ZipFile", return_value=mock_zip_ctx)
        mocker.patch.object(cs, "_check_file_integrity", return_value=True)

        sample = Sample(SHA256)
        cs.download_malware_sample(sample)

        assert sample.downloaded_successfully is True
        assert sample.zipped_path == str(tmp_path / (SHA256 + ".zip"))
        assert sample.unzipped_path == tmp_path / pathlib.Path(SHA256)


# ---------------------------------------------------------------------------
# _check_file_integrity
# ---------------------------------------------------------------------------

class TestCheckFileIntegrity:
    def test_matching_sha256_returns_true(self, cs, tmp_path):
        content = b"hello world"
        expected = hashlib.sha256(content).hexdigest()
        file_path = tmp_path / expected
        file_path.write_bytes(content)

        sample = Sample(expected)
        sample.unzipped_path = file_path
        assert cs._check_file_integrity(sample) is True

    def test_mismatched_sha256_returns_false(self, cs, tmp_path):
        content = b"tampered content"
        file_path = tmp_path / "somefile"
        file_path.write_bytes(content)

        sample = Sample("wrong_expected_hash")
        sample.unzipped_path = file_path
        assert cs._check_file_integrity(sample) is False

    def test_empty_file(self, cs, tmp_path):
        content = b""
        expected = hashlib.sha256(content).hexdigest()
        file_path = tmp_path / expected
        file_path.write_bytes(content)

        sample = Sample(expected)
        sample.unzipped_path = file_path
        assert cs._check_file_integrity(sample) is True


# ---------------------------------------------------------------------------
# check_ioc
# ---------------------------------------------------------------------------

class TestCheckIOC:
    def test_returns_true_when_resources_present(self, cs):
        cs.ioc_api.indicator_search.return_value = {
            "body": {"resources": ["existing_ioc"], "errors": None}
        }
        assert cs.check_ioc("sha256", SHA256) is True

    def test_returns_false_when_resources_empty(self, cs):
        cs.ioc_api.indicator_search.return_value = {
            "body": {"resources": [], "errors": None}
        }
        assert cs.check_ioc("sha256", SHA256) is False

    def test_returns_false_on_api_error(self, cs):
        cs.ioc_api.indicator_search.return_value = make_error_response("search failed")
        assert cs.check_ioc("sha256", SHA256) is False

    def test_returns_false_on_exception(self, cs):
        cs.ioc_api.indicator_search.side_effect = Exception("network error")
        assert cs.check_ioc("sha256", SHA256) is False

    def test_returns_false_when_resources_none(self, cs):
        cs.ioc_api.indicator_search.return_value = {
            "body": {"resources": None, "errors": None}
        }
        assert cs.check_ioc("sha256", SHA256) is False

    def test_escapes_single_quote_in_value(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.check_ioc("domain", "test'evil.com")
        filter_arg = cs.ioc_api.indicator_search.call_args.kwargs["filter"]
        assert "test'evil.com" not in filter_arg
        assert "test\\'evil.com" in filter_arg


# ---------------------------------------------------------------------------
# create_ioc
# ---------------------------------------------------------------------------

class TestCreateIOC:
    def _make_sample(self, sha256=None, ipv4=None, domains=None, extra_sha256s=None):
        s = Sample(sha256 or SHA256)
        s.vmray_result = {
            "ipv4": set(ipv4 or []),
            "sha256": set(extra_sha256s or []),
            "domain": set(domains or []),
        }
        return s

    def _ok_response(self):
        return {"body": {"errors": None, "resources": ["ok"]}}

    def test_creates_sha256_ioc_when_not_exists(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.ioc_api.indicator_create.return_value = self._ok_response()
        sample = self._make_sample()
        cs.create_ioc(sample)
        cs.ioc_api.indicator_create.assert_called_once()
        call_kwargs = cs.ioc_api.indicator_create.call_args.kwargs
        assert call_kwargs["type"] == "sha256"
        assert call_kwargs["value"] == SHA256
        assert call_kwargs["action"] == IOC_ACTION_PREVENT

    def test_skips_sha256_ioc_when_already_exists(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [SHA256], "errors": None}}
        sample = self._make_sample()
        cs.create_ioc(sample)
        cs.ioc_api.indicator_create.assert_not_called()

    def test_creates_ipv4_ioc(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.ioc_api.indicator_create.return_value = self._ok_response()
        sample = self._make_sample(ipv4=["1.2.3.4"])
        cs.create_ioc(sample)
        calls = [c.kwargs for c in cs.ioc_api.indicator_create.call_args_list]
        ipv4_calls = [c for c in calls if c.get("type") == "ipv4"]
        assert len(ipv4_calls) == 1
        assert ipv4_calls[0]["value"] == "1.2.3.4"
        assert ipv4_calls[0]["action"] == IOC_ACTION_DETECT

    def test_creates_domain_ioc(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.ioc_api.indicator_create.return_value = self._ok_response()
        sample = self._make_sample(domains=["evil.example.com"])
        cs.create_ioc(sample)
        calls = [c.kwargs for c in cs.ioc_api.indicator_create.call_args_list]
        domain_calls = [c for c in calls if c.get("type") == "domain"]
        assert len(domain_calls) == 1
        assert domain_calls[0]["value"] == "evil.example.com"
        assert domain_calls[0]["action"] == IOC_ACTION_DETECT

    def test_creates_additional_sha256_from_vmray_result(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.ioc_api.indicator_create.return_value = self._ok_response()
        extra_sha = "d" * 64
        sample = self._make_sample(extra_sha256s=[extra_sha])
        cs.create_ioc(sample)
        calls = [c.kwargs for c in cs.ioc_api.indicator_create.call_args_list]
        sha_values = [c["value"] for c in calls if c.get("type") == "sha256"]
        assert extra_sha in sha_values

    def test_ioc_create_error_does_not_raise(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.ioc_api.indicator_create.return_value = make_error_response("create failed")
        sample = self._make_sample()
        cs.create_ioc(sample)  # should not raise

    def test_exception_during_ioc_does_not_propagate(self, cs):
        cs.ioc_api.indicator_search.side_effect = Exception("unexpected")
        sample = self._make_sample()
        cs.create_ioc(sample)  # should not raise

    def test_ioc_applied_globally_and_tagged(self, cs):
        cs.ioc_api.indicator_search.return_value = {"body": {"resources": [], "errors": None}}
        cs.ioc_api.indicator_create.return_value = self._ok_response()
        sample = self._make_sample()
        cs.create_ioc(sample)
        kwargs = cs.ioc_api.indicator_create.call_args.kwargs
        assert kwargs["applied_globally"] is True
        assert IOC_TAGS == kwargs["tags"]
        assert IOC_PLATFORMS == kwargs["platforms"]
        assert kwargs["severity"] == IOC_SEVERITY


# ---------------------------------------------------------------------------
# update_quarantine
# ---------------------------------------------------------------------------

class TestUpdateQuarantine:
    def test_calls_api_with_correct_args(self, cs):
        cs.quarantine_api.update_quarantined_detects_by_id.return_value = {
            "status_code": 200,
            "body": {"errors": None},
        }
        cs.update_quarantine("q1", "malicious comment", "unrelease")
        cs.quarantine_api.update_quarantined_detects_by_id.assert_called_once_with(
            ids="q1", comment="malicious comment", action="unrelease"
        )

    def test_non_200_status_logs_error_but_does_not_raise(self, cs):
        cs.quarantine_api.update_quarantined_detects_by_id.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "bad request"}]},
        }
        cs.update_quarantine("q1", "comment", "release")  # should not raise

    def test_api_exception_does_not_propagate(self, cs):
        cs.quarantine_api.update_quarantined_detects_by_id.side_effect = Exception("timeout")
        cs.update_quarantine("q1", "comment", "release")  # should not raise

    def test_body_errors_logs_but_does_not_raise(self, cs):
        cs.quarantine_api.update_quarantined_detects_by_id.return_value = {
            "status_code": 200,
            "body": {"errors": [{"message": "partial error"}]},
        }
        cs.update_quarantine("q1", "comment", "unrelease")  # should not raise


# ---------------------------------------------------------------------------
# update_alert
# ---------------------------------------------------------------------------

class TestUpdateAlert:
    def test_calls_api_with_correct_args(self, cs):
        cs.alerts_api.update_alerts_v3.return_value = {
            "status_code": 200,
            "body": {"errors": None},
        }
        cs.update_alert("comp1", "test comment")
        cs.alerts_api.update_alerts_v3.assert_called_once_with(
            composite_ids=["comp1"], append_comment="test comment"
        )

    def test_non_200_status_does_not_raise(self, cs):
        cs.alerts_api.update_alerts_v3.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "not found"}]},
        }
        cs.update_alert("comp1", "comment")  # should not raise

    def test_api_exception_does_not_propagate(self, cs):
        cs.alerts_api.update_alerts_v3.side_effect = Exception("service unavailable")
        cs.update_alert("comp1", "comment")  # should not raise


# ---------------------------------------------------------------------------
# build_detection_comments
# ---------------------------------------------------------------------------

class TestBuildDetectionComments:
    def _make_sample(self, verdict, webif_url="", threat_names=None,
                     classifications=None, vtis=None):
        s = Sample(SHA256)
        s.vmray_verdict = verdict
        s.vmray_metadata = {"sample_webif_url": webif_url} if webif_url else {}
        s.vmray_result = {
            "threat_names": set(threat_names or []),
            "classifications": set(classifications or []),
        }
        s.vmray_vtis = vtis or []
        return s

    def test_clean_verdict_returns_single_clean_message(self):
        s = self._make_sample(VERDICT.CLEAN)
        result = CrowdStrike.build_detection_comments(s)
        assert result == ["[VMRay] Verdict: Clean — no threats detected."]

    def test_malicious_verdict_includes_verdict_section(self):
        s = self._make_sample(VERDICT.MALICIOUS)
        result = CrowdStrike.build_detection_comments(s)
        assert any("[VMRay] Verdict: Malicious" in c for c in result)

    def test_suspicious_verdict_includes_verdict_section(self):
        s = self._make_sample(VERDICT.SUSPICIOUS)
        result = CrowdStrike.build_detection_comments(s)
        assert any("[VMRay] Verdict: Suspicious" in c for c in result)

    def test_webif_url_included_in_verdict_section(self):
        s = self._make_sample(VERDICT.MALICIOUS, webif_url="https://vmray.example.com/1")
        result = CrowdStrike.build_detection_comments(s)
        assert any("https://vmray.example.com/1" in c for c in result)

    def test_threat_names_section_present(self):
        s = self._make_sample(VERDICT.MALICIOUS, threat_names=["TrojanGeneric"])
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "Threat Names:" in full
        assert "TrojanGeneric" in full

    def test_classifications_section_present(self):
        s = self._make_sample(VERDICT.MALICIOUS, classifications=["Trojan", "Dropper"])
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "Classifications:" in full
        assert "Trojan" in full

    def test_vtis_section_present(self):
        vtis = [{"category": "Process", "operation": "Spawned child", "score": 9}]
        s = self._make_sample(VERDICT.MALICIOUS, vtis=vtis)
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "VTIs (Score | Category | Operation):" in full
        assert "9 | Process | Spawned child" in full

    def test_vti_without_score_uses_arrow_notation(self):
        vtis = [{"category": "Network", "operation": "DNS query", "score": ""}]
        s = self._make_sample(VERDICT.MALICIOUS, vtis=vtis)
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "Network | DNS query" in full

    def test_no_optional_sections_gives_single_comment(self):
        s = self._make_sample(VERDICT.MALICIOUS)
        result = CrowdStrike.build_detection_comments(s)
        assert len(result) == 1

    def test_all_comments_within_max_length(self):
        threat_names = ["T" * 900]
        classifications = ["C" * 900]
        s = self._make_sample(
            VERDICT.MALICIOUS,
            threat_names=threat_names,
            classifications=classifications,
        )
        result = CrowdStrike.build_detection_comments(s)
        for comment in result:
            assert len(comment) <= MAX_COMMENT_LENGTH

    def test_sections_split_when_too_long(self):
        s = self._make_sample(
            VERDICT.MALICIOUS,
            threat_names=["T" * 900],
            classifications=["C" * 900],
        )
        result = CrowdStrike.build_detection_comments(s)
        assert len(result) >= 2

    def test_returns_list(self):
        s = self._make_sample(VERDICT.MALICIOUS)
        assert isinstance(CrowdStrike.build_detection_comments(s), list)

    def test_always_at_least_one_comment(self):
        s = self._make_sample(VERDICT.MALICIOUS)
        assert len(CrowdStrike.build_detection_comments(s)) >= 1

    def test_threat_names_sorted(self):
        s = self._make_sample(VERDICT.MALICIOUS, threat_names=["Zeta", "Alpha", "Beta"])
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        idx_alpha = full.index("Alpha")
        idx_beta = full.index("Beta")
        idx_zeta = full.index("Zeta")
        assert idx_alpha < idx_beta < idx_zeta

    def test_intra_section_split_classifications(self):
        # 3 items each ~400 chars → single section > 1024, must split into multiple chunks
        items = ["A" * 400, "B" * 400, "C" * 400]
        s = self._make_sample(VERDICT.MALICIOUS, classifications=items)
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "Classifications:" in full
        assert "Classifications (cont.):" in full
        for comment in result:
            assert len(comment) <= MAX_COMMENT_LENGTH

    def test_webif_url_uses_pipe_separator(self):
        s = self._make_sample(VERDICT.MALICIOUS, webif_url="https://vmray.example.com/1")
        result = CrowdStrike.build_detection_comments(s)
        assert any("| Analysis: https://vmray.example.com/1" in c for c in result)

    def test_vti_format_uses_pipe_notation(self):
        vtis = [{"category": "Network", "operation": "DNS query", "score": 5}]
        s = self._make_sample(VERDICT.MALICIOUS, vtis=vtis)
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "5 | Network | DNS query" in full

    def test_vtis_one_line_per_entry(self):
        vtis = [
            {"category": "Obfuscation", "operation": "Resolves API dynamically", "score": 1},
            {"category": "Network", "operation": "DNS query", "score": 2},
            {"category": "Obfuscation", "operation": "Overwrites code", "score": 1},
        ]
        s = self._make_sample(VERDICT.MALICIOUS, vtis=vtis)
        result = CrowdStrike.build_detection_comments(s)
        full = "\n\n".join(result)
        assert "1 | Obfuscation | Resolves API dynamically" in full
        assert "1 | Obfuscation | Overwrites code" in full
        assert "2 | Network | DNS query" in full
        assert full.count("| Obfuscation |") == 2
        # score 2 appears before score 1 entries
        assert full.index("2 | Network") < full.index("1 | Obfuscation")
