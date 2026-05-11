"""Tests for the connector.run() orchestration function."""

import os
import pathlib
from unittest.mock import MagicMock, call, patch

import pytest

from config.general_conf import GeneralConfig, VERDICT
from config.crowdstrike_conf import CrowdStrikeConfig, DATA_SOURCE
from config.vmray_conf import VMRayConfig
from lib.CrowdStrike import ConnectorDetect, ConnectorQuarantine
from lib.Sample import Sample
import logging

from connector import run, _setup_logging

SHA256 = "f" * 64
SHA256_B = "0" * 64


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def env(mocker, tmp_path):
    """Patch all I/O and external dependencies so run() executes in-process."""
    log_dir = tmp_path / "log"
    log_file = log_dir / "cs-connector.log"
    dl_dir = tmp_path / "downloads"

    mocker.patch.object(GeneralConfig, "LOG_DIR", log_dir)
    mocker.patch.object(GeneralConfig, "LOG_FILE_PATH", log_file)
    mocker.patch.object(CrowdStrikeConfig, "DOWNLOAD_DIR_PATH", dl_dir)
    mocker.patch("connector._setup_logging")

    mock_cs_cls = mocker.patch("connector.CrowdStrike")
    mock_vmray_cls = mocker.patch("connector.VMRay")

    mock_cs = MagicMock()
    mock_vmray = MagicMock()
    mock_cs_cls.return_value = mock_cs
    mock_vmray_cls.return_value = mock_vmray

    mocker.patch.object(
        CrowdStrikeConfig,
        "SELECTED_DATA_SOURCES",
        [DATA_SOURCE.ALERT, DATA_SOURCE.QUARANTINE],
    )
    mocker.patch.object(CrowdStrikeConfig, "COMMENT_TO_DETECTION", True)
    mocker.patch.object(CrowdStrikeConfig, "COMMENT_TO_QUARANTINE", True)
    mocker.patch.object(VMRayConfig, "RESUBMIT", False)

    # Default: no data
    mock_cs.get_quarantines.return_value = []
    mock_cs.get_alerts.return_value = []
    mock_cs.extract_hash_from_quarantines.return_value = []
    mock_cs.extract_hashes_from_alerts.return_value = []
    mock_vmray.get_sample_summary.return_value = None

    return {
        "cs": mock_cs,
        "vmray": mock_vmray,
        "cs_cls": mock_cs_cls,
        "vmray_cls": mock_vmray_cls,
        "tmp_path": tmp_path,
    }


def _make_detect(sha256=SHA256, composite_id="c1"):
    return ConnectorDetect(
        composite_id=composite_id,
        timestamp="2024-01-01T00:00:00Z",
        host_id="h1",
        included_sha256=sha256,
        os_version="Windows 10",
        device_id="d1",
        file_path="/f",
    )


def _make_quarantine(sha256=SHA256, qid="q1"):
    return ConnectorQuarantine(
        quarantine_id=qid,
        timestamp="2024-01-01T00:00:00Z",
        sha256_hash=sha256,
        hostname="host1",
        filename="mal.exe",
        quarantine_host_id="aid1",
    )


def _configure_sample_in_db(env, sha256=SHA256, verdict_str="malicious", metadata=None):
    """Make VMRay return a sample already in its database."""
    if metadata is None:
        metadata = {
            "sample_id": 1,
            "sample_verdict": verdict_str,
            "sample_webif_url": "https://vmray.example.com/1",
        }
    env["vmray"].get_sample_summary.return_value = metadata
    env["vmray"].parse_sample_summary_data.return_value = metadata

    def add_results(sample, sample_summary=None):
        sample.vmray_metadata = metadata
        sample.vmray_result = {
            "sha256": set(),
            "ipv4": set(),
            "domain": set(),
            "threat_names": set(),
            "classifications": set(),
        }
        verdict_map = {
            "malicious": VERDICT.MALICIOUS,
            "suspicious": VERDICT.SUSPICIOUS,
        }
        sample.vmray_verdict = verdict_map.get(verdict_str, VERDICT.CLEAN)

    env["vmray"].add_sample_results.side_effect = add_results


# ---------------------------------------------------------------------------
# Initialisation failures
# ---------------------------------------------------------------------------

class TestInitFailures:
    def test_crowdstrike_init_failure_returns_early(self, env):
        env["cs_cls"].side_effect = Exception("CS auth failed")
        run()
        env["vmray_cls"].assert_not_called()

    def test_vmray_init_failure_returns_early(self, env):
        env["vmray_cls"].side_effect = Exception("VMRay auth failed")
        run()
        env["vmray"].get_sample_summary.assert_not_called()


# ---------------------------------------------------------------------------
# No data / early exit
# ---------------------------------------------------------------------------

class TestNoData:
    def test_no_hashes_returns_early(self, env):
        run()
        env["vmray"].get_sample_summary.assert_not_called()

    def test_quarantine_only_source_processes_quarantines(self, env, mocker):
        mocker.patch.object(
            CrowdStrikeConfig, "SELECTED_DATA_SOURCES", [DATA_SOURCE.QUARANTINE]
        )
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        _configure_sample_in_db(env)

        run()

        env["cs"].get_quarantines.assert_called_once()
        env["cs"].get_alerts.assert_not_called()

    def test_alert_only_source_processes_alerts(self, env, mocker):
        mocker.patch.object(
            CrowdStrikeConfig, "SELECTED_DATA_SOURCES", [DATA_SOURCE.ALERT]
        )
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env)

        run()

        env["cs"].get_alerts.assert_called_once()
        env["cs"].get_quarantines.assert_not_called()

    def test_both_sources_called_by_default(self, env):
        q = _make_quarantine(sha256=SHA256_B)
        d = _make_detect(sha256=SHA256)
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256_B]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env)

        run()

        env["cs"].get_quarantines.assert_called_once()
        env["cs"].get_alerts.assert_called_once()

    def test_empty_data_sources_logs_and_returns(self, env, mocker):
        mocker.patch.object(CrowdStrikeConfig, "SELECTED_DATA_SOURCES", [])
        run()
        env["vmray"].get_sample_summary.assert_not_called()


# ---------------------------------------------------------------------------
# VMRay DB lookup paths
# ---------------------------------------------------------------------------

class TestVMRayDBLookup:
    def test_sample_not_in_db_goes_to_download(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None

        run()

        env["cs"].download_malware_sample.assert_called_once()
        call_args = env["cs"].download_malware_sample.call_args[0][0]
        assert call_args.sample_sha256 == SHA256

    def test_sample_found_in_db_no_resubmit_skips_download(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env)

        run()

        env["cs"].download_malware_sample.assert_not_called()

    def test_sample_found_in_db_with_resubmit_queues_for_download(self, env, mocker):
        mocker.patch.object(VMRayConfig, "RESUBMIT", True)
        mocker.patch.object(VMRayConfig, "RESUBMISSION_VERDICTS", [VERDICT.MALICIOUS])

        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious")

        run()

        env["cs"].download_malware_sample.assert_called_once()

    def test_sample_found_in_db_verdict_not_in_resubmit_list_skips(self, env, mocker):
        mocker.patch.object(VMRayConfig, "RESUBMIT", True)
        mocker.patch.object(VMRayConfig, "RESUBMISSION_VERDICTS", [VERDICT.SUSPICIOUS])

        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious")

        run()

        env["cs"].download_malware_sample.assert_not_called()


# ---------------------------------------------------------------------------
# Action skip guards
# ---------------------------------------------------------------------------

class TestActionGuards:
    def _setup_downloaded(self, env, metadata):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious", metadata=metadata)

    def test_skips_when_download_failed(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None

        env["cs"].download_malware_sample.side_effect = lambda s: setattr(
            s, "downloaded_successfully", False
        )
        run()

        env["cs"].update_alert.assert_not_called()
        env["cs"].create_ioc.assert_not_called()

    def test_skips_when_no_vmray_metadata(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]

        meta = {"sample_id": 1, "sample_verdict": "malicious"}
        env["vmray"].get_sample_summary.return_value = meta
        env["vmray"].parse_sample_summary_data.return_value = meta

        def add_results_no_meta(sample):
            sample.vmray_metadata = {}
            sample.vmray_result = {}

        env["vmray"].add_sample_results.side_effect = add_results_no_meta

        run()

        env["cs"].update_alert.assert_not_called()


# ---------------------------------------------------------------------------
# Comment posting
# ---------------------------------------------------------------------------

class TestCommentPosting:
    def test_posts_comment_to_detection_on_malicious(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious")
        env["cs"].build_detection_comments.return_value = ["VMRay result: malicious"]

        run()

        env["cs"].update_alert.assert_called_once_with("c1", comment="VMRay result: malicious")

    def test_posts_multiple_comments_when_build_returns_multiple(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="suspicious")
        env["cs"].build_detection_comments.return_value = ["comment1", "comment2"]

        run()

        assert env["cs"].update_alert.call_count == 2

    def test_no_comment_when_comment_to_detection_false(self, env, mocker):
        mocker.patch.object(CrowdStrikeConfig, "COMMENT_TO_DETECTION", False)
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious")

        run()

        env["cs"].update_alert.assert_not_called()

    def test_no_comment_when_no_matching_detections(self, env, mocker):
        mocker.patch.object(
            CrowdStrikeConfig, "SELECTED_DATA_SOURCES", [DATA_SOURCE.QUARANTINE]
        )
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious")

        run()

        env["cs"].update_alert.assert_not_called()


# ---------------------------------------------------------------------------
# IOC creation
# ---------------------------------------------------------------------------

class TestIOCCreation:
    def test_creates_ioc_for_malicious(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="malicious")
        env["cs"].build_detection_comments.return_value = ["comment"]

        run()

        env["cs"].create_ioc.assert_called_once()
        sample_arg = env["cs"].create_ioc.call_args.kwargs["sample"]
        assert sample_arg.sample_sha256 == SHA256

    def test_no_ioc_for_suspicious(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="suspicious")
        env["cs"].build_detection_comments.return_value = ["comment"]

        run()

        env["cs"].create_ioc.assert_not_called()

    def test_no_ioc_for_clean(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="clean")
        env["cs"].build_detection_comments.return_value = ["comment"]

        run()

        env["cs"].create_ioc.assert_not_called()


# ---------------------------------------------------------------------------
# Quarantine updates
# ---------------------------------------------------------------------------

class TestQuarantineUpdates:
    def test_malicious_quarantine_gets_unrelease(self, env):
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        env["cs"].get_alerts.return_value = []
        env["cs"].extract_hashes_from_alerts.return_value = []
        _configure_sample_in_db(env, verdict_str="malicious")

        run()

        env["cs"].update_quarantine.assert_called_once()
        call_kwargs = env["cs"].update_quarantine.call_args
        assert call_kwargs.kwargs["action"] == "unrelease"
        assert "malicious" in call_kwargs.kwargs["comment"].lower()

    def test_suspicious_quarantine_gets_unrelease(self, env):
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        env["cs"].get_alerts.return_value = []
        env["cs"].extract_hashes_from_alerts.return_value = []
        _configure_sample_in_db(env, verdict_str="suspicious")

        run()

        call_kwargs = env["cs"].update_quarantine.call_args
        assert call_kwargs.kwargs["action"] == "unrelease"

    def test_clean_quarantine_gets_release(self, env):
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        env["cs"].get_alerts.return_value = []
        env["cs"].extract_hashes_from_alerts.return_value = []
        _configure_sample_in_db(env, verdict_str="clean")

        run()

        call_kwargs = env["cs"].update_quarantine.call_args
        assert call_kwargs.kwargs["action"] == "release"

    def test_no_quarantine_update_when_flag_false(self, env, mocker):
        mocker.patch.object(CrowdStrikeConfig, "COMMENT_TO_QUARANTINE", False)
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        env["cs"].get_alerts.return_value = []
        env["cs"].extract_hashes_from_alerts.return_value = []
        _configure_sample_in_db(env, verdict_str="malicious")

        run()

        env["cs"].update_quarantine.assert_not_called()

    def test_no_quarantine_update_when_no_matching_quarantine(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["cs"].get_quarantines.return_value = []
        env["cs"].extract_hash_from_quarantines.return_value = []
        _configure_sample_in_db(env, verdict_str="malicious")
        env["cs"].build_detection_comments.return_value = ["comment"]

        run()

        env["cs"].update_quarantine.assert_not_called()


# ---------------------------------------------------------------------------
# File cleanup
# ---------------------------------------------------------------------------

class TestFileCleanup:
    def test_downloaded_files_cleaned_up_on_success(self, env, tmp_path):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None

        zip_file = tmp_path / f"{SHA256}.zip"
        unzipped = tmp_path / SHA256
        zip_file.write_bytes(b"zip")
        unzipped.write_bytes(b"raw")

        def setup_download(sample):
            sample.downloaded_successfully = True
            sample.zipped_path = str(zip_file)
            sample.unzipped_path = str(unzipped)

        env["cs"].download_malware_sample.side_effect = setup_download
        env["vmray"].wait_submissions.return_value = None

        run()

        assert not zip_file.exists()
        assert not unzipped.exists()

    def test_cleanup_runs_even_when_processing_raises(self, env, tmp_path, mocker):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None

        zip_file = tmp_path / f"{SHA256}.zip"
        unzipped = tmp_path / SHA256
        zip_file.write_bytes(b"zip")
        unzipped.write_bytes(b"raw")

        def setup_download(sample):
            sample.downloaded_successfully = True
            sample.zipped_path = str(zip_file)
            sample.unzipped_path = str(unzipped)

        env["cs"].download_malware_sample.side_effect = setup_download
        env["vmray"].wait_submissions.side_effect = RuntimeError("unexpected crash")

        run()  # should not raise

        assert not zip_file.exists()
        assert not unzipped.exists()

    def test_missing_files_do_not_cause_cleanup_error(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None

        def setup_download(sample):
            sample.downloaded_successfully = True
            sample.zipped_path = "/nonexistent/path.zip"
            sample.unzipped_path = "/nonexistent/path"

        env["cs"].download_malware_sample.side_effect = setup_download
        env["vmray"].wait_submissions.return_value = None

        run()  # should not raise

    def test_no_cleanup_when_no_downloads(self, env):
        _configure_sample_in_db(env, verdict_str="malicious")
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["cs"].build_detection_comments.return_value = ["comment"]

        mock_remove = patch("connector.os.remove")
        with mock_remove as m:
            run()
            m.assert_not_called()


# ---------------------------------------------------------------------------
# CrowdStrike API errors during data fetch
# ---------------------------------------------------------------------------

class TestDataFetchErrors:
    def test_quarantine_fetch_exception_continues_with_alerts(self, env):
        env["cs"].get_quarantines.side_effect = Exception("quarantine API down")
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="clean")

        run()  # should not crash, alerts still processed

        env["vmray"].get_sample_summary.assert_called()

    def test_alert_fetch_exception_continues_with_quarantines(self, env):
        env["cs"].get_alerts.side_effect = Exception("alerts API down")
        q = _make_quarantine()
        env["cs"].get_quarantines.return_value = [q]
        env["cs"].extract_hash_from_quarantines.return_value = [SHA256]
        _configure_sample_in_db(env, verdict_str="clean")

        run()

        env["vmray"].get_sample_summary.assert_called()


# ---------------------------------------------------------------------------
# _setup_logging
# ---------------------------------------------------------------------------

class TestSetupLogging:
    def test_setup_logging_installs_handlers(self, tmp_path, mocker):
        log_file = tmp_path / "test.log"
        log_file.touch()
        mocker.patch.object(GeneralConfig, "LOG_FILE_PATH", log_file)

        root = logging.getLogger()
        saved = root.handlers[:]
        root.handlers.clear()
        try:
            _setup_logging()
            handler_types = [type(h) for h in root.handlers]
            assert logging.FileHandler in handler_types
            assert logging.StreamHandler in handler_types
        finally:
            for h in root.handlers:
                h.close()
            root.handlers = saved


# ---------------------------------------------------------------------------
# VMRay analysis not finished
# ---------------------------------------------------------------------------

class TestSubmissionNotFinished:
    def test_skips_actions_when_submission_not_finished(self, env):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None

        def setup_download(sample):
            sample.downloaded_successfully = True

        def setup_submit(sample):
            sample.vmray_submit_successfully = True
            # vmray_submission_finished stays False

        env["cs"].download_malware_sample.side_effect = setup_download
        env["vmray"].submit_sample.side_effect = setup_submit
        env["vmray"].wait_submissions.return_value = None

        run()

        env["cs"].update_alert.assert_not_called()
        env["cs"].create_ioc.assert_not_called()


# ---------------------------------------------------------------------------
# Cleanup OSError handling
# ---------------------------------------------------------------------------

class TestCleanupErrors:
    def _setup_download(self, env, zip_file, unzipped):
        d = _make_detect()
        env["cs"].get_alerts.return_value = [d]
        env["cs"].extract_hashes_from_alerts.return_value = [SHA256]
        env["vmray"].get_sample_summary.return_value = None
        env["vmray"].wait_submissions.return_value = None

        def setup_download(sample):
            sample.downloaded_successfully = True
            sample.zipped_path = str(zip_file)
            sample.unzipped_path = str(unzipped)

        env["cs"].download_malware_sample.side_effect = setup_download

    def test_cleanup_logs_error_when_remove_zipped_fails(self, env, tmp_path, mocker):
        zip_file = tmp_path / f"{SHA256}.zip"
        unzipped = tmp_path / SHA256
        zip_file.write_bytes(b"zip")
        unzipped.write_bytes(b"raw")
        self._setup_download(env, zip_file, unzipped)

        call_count = 0

        def remove_side_effect(path):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("permission denied")

        mocker.patch("connector.os.remove", side_effect=remove_side_effect)

        run()  # must not raise

    def test_cleanup_logs_error_when_remove_unzipped_fails(self, env, tmp_path, mocker):
        zip_file = tmp_path / f"{SHA256}.zip"
        unzipped = tmp_path / SHA256
        zip_file.write_bytes(b"zip")
        unzipped.write_bytes(b"raw")
        self._setup_download(env, zip_file, unzipped)

        call_count = 0

        def remove_side_effect(path):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise OSError("permission denied")

        mocker.patch("connector.os.remove", side_effect=remove_side_effect)

        run()  # must not raise
