"""Tests for crowdstrike_conf.py — enums, types, and action flags."""

import pathlib

import pytest

from config.crowdstrike_conf import DATA_SOURCE, CrowdStrikeConfig
from config.general_conf import GeneralConfig


class TestDATA_SOURCE:
    def test_quarantine_value(self):
        assert DATA_SOURCE.QUARANTINE.value == "Quarantine"

    def test_alert_value(self):
        assert DATA_SOURCE.ALERT.value == "Alert"

    def test_members_distinct(self):
        assert DATA_SOURCE.QUARANTINE != DATA_SOURCE.ALERT


class TestCrowdStrikeConfig:
    def test_download_dir_path_is_path(self):
        assert isinstance(CrowdStrikeConfig.DOWNLOAD_DIR_PATH, pathlib.Path)

    def test_time_span_larger_than_general(self):
        assert CrowdStrikeConfig.TIME_SPAN > GeneralConfig.TIME_SPAN

    def test_selected_data_sources_is_list(self):
        assert isinstance(CrowdStrikeConfig.SELECTED_DATA_SOURCES, list)

    def test_comment_to_detection_is_bool(self):
        assert isinstance(CrowdStrikeConfig.COMMENT_TO_DETECTION, bool)

    def test_comment_to_quarantine_is_bool(self):
        assert isinstance(CrowdStrikeConfig.COMMENT_TO_QUARANTINE, bool)

    def test_client_id_is_str(self):
        assert isinstance(CrowdStrikeConfig.CLIENT_ID, str)

    def test_client_secret_is_str(self):
        assert isinstance(CrowdStrikeConfig.CLIENT_SECRET, str)

    def test_base_url_is_str(self):
        assert isinstance(CrowdStrikeConfig.BASE_URL, str)

    def test_default_base_url_is_https(self):
        from config.constants import CS_BASE_URL
        assert CS_BASE_URL.startswith("https://")
