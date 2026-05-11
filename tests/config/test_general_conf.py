"""Tests for general_conf.py — enums, defaults, and types."""

import logging
import pathlib

import pytest

from config.general_conf import VERDICT, RUNTIME_MODE, GeneralConfig


class TestVERDICT:
    def test_malicious_value(self):
        assert VERDICT.MALICIOUS.value == "malicious"

    def test_suspicious_value(self):
        assert VERDICT.SUSPICIOUS.value == "suspicious"

    def test_clean_value(self):
        assert VERDICT.CLEAN.value == "clean"

    def test_members_are_distinct(self):
        assert VERDICT.MALICIOUS != VERDICT.SUSPICIOUS
        assert VERDICT.MALICIOUS != VERDICT.CLEAN
        assert VERDICT.SUSPICIOUS != VERDICT.CLEAN

    def test_enum_from_value(self):
        assert VERDICT("malicious") is VERDICT.MALICIOUS
        assert VERDICT("suspicious") is VERDICT.SUSPICIOUS
        assert VERDICT("clean") is VERDICT.CLEAN


class TestRUNTIME_MODE:
    def test_docker_value(self):
        assert RUNTIME_MODE.DOCKER.value == "DOCKER"

    def test_cli_value(self):
        assert RUNTIME_MODE.CLI.value == "CLI"

    def test_members_are_distinct(self):
        assert RUNTIME_MODE.DOCKER != RUNTIME_MODE.CLI


class TestGeneralConfig:
    def test_log_dir_is_path(self):
        assert isinstance(GeneralConfig.LOG_DIR, pathlib.Path)

    def test_log_file_path_is_path(self):
        assert isinstance(GeneralConfig.LOG_FILE_PATH, pathlib.Path)

    def test_log_file_inside_log_dir(self):
        assert GeneralConfig.LOG_FILE_PATH.parent == GeneralConfig.LOG_DIR

    def test_selected_verdicts_contains_malicious(self):
        assert VERDICT.MALICIOUS.value in GeneralConfig.SELECTED_VERDICTS

    def test_selected_verdicts_is_list(self):
        assert isinstance(GeneralConfig.SELECTED_VERDICTS, list)

    def test_time_span_is_positive_int(self):
        assert isinstance(GeneralConfig.TIME_SPAN, int)
        assert GeneralConfig.TIME_SPAN > 0

    def test_log_level_is_int(self):
        assert isinstance(GeneralConfig.LOG_LEVEL, int)
