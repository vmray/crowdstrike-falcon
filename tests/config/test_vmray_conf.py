"""Tests for vmray_conf.py — types and defaults."""

import pytest

from config.vmray_conf import VMRayConfig
from config.general_conf import VERDICT


class TestVMRayConfig:
    def test_api_key_is_str(self):
        assert isinstance(VMRayConfig.API_KEY, str)

    def test_url_is_str(self):
        assert isinstance(VMRayConfig.URL, str)
        assert VMRayConfig.URL.startswith("https://")

    def test_ssl_verify_is_bool(self):
        assert isinstance(VMRayConfig.SSL_VERIFY, bool)

    def test_submission_tags_is_list(self):
        assert isinstance(VMRayConfig.SUBMISSION_TAGS, list)
        assert len(VMRayConfig.SUBMISSION_TAGS) > 0

    def test_analysis_timeout_positive(self):
        assert isinstance(VMRayConfig.ANALYSIS_TIMEOUT, int)
        assert VMRayConfig.ANALYSIS_TIMEOUT > 0

    def test_analysis_job_timeout_positive(self):
        assert isinstance(VMRayConfig.ANALYSIS_JOB_TIMEOUT, int)
        assert VMRayConfig.ANALYSIS_JOB_TIMEOUT > 0

    def test_poll_interval_positive(self):
        assert isinstance(VMRayConfig.POLL_INTERVAL, int)
        assert VMRayConfig.POLL_INTERVAL > 0

    def test_resubmit_is_bool(self):
        assert isinstance(VMRayConfig.RESUBMIT, bool)

    def test_resubmission_verdicts_is_list(self):
        assert isinstance(VMRayConfig.RESUBMISSION_VERDICTS, list)

    def test_resubmission_verdicts_contains_verdict_enums(self):
        for v in VMRayConfig.RESUBMISSION_VERDICTS:
            assert isinstance(v, VERDICT)

    def test_connector_name_is_str(self):
        assert isinstance(VMRayConfig.CONNECTOR_NAME, str)
