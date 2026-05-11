"""Tests for the Sample DTO."""

import pytest

from lib.Sample import Sample
from config.general_conf import VERDICT

SHA256 = "b" * 64


class TestSampleInit:
    def test_sha256_stored(self):
        s = Sample(SHA256)
        assert s.sample_sha256 == SHA256

    def test_defaults(self):
        s = Sample(SHA256)
        assert s.zipped_path == ""
        assert s.unzipped_path == ""
        assert s.downloaded_successfully is False
        assert s.vmray_metadata == {}
        assert s.vmray_result == {}
        assert s.vmray_vtis == []
        assert s.vmray_submit_successfully is False
        assert s.vmray_submission_finished is False
        assert s.vmray_verdict == VERDICT.SUSPICIOUS
        assert s.vmray_submission_id == ""
        assert s.vmray_sample_id == ""

    def test_custom_vmray_result(self):
        result = {"sha256": {"abc"}, "ipv4": set()}
        s = Sample(SHA256, vmray_result=result)
        assert s.vmray_result is result

    def test_none_vmray_result_becomes_empty_dict(self):
        s = Sample(SHA256, vmray_result=None)
        assert s.vmray_result == {}

    def test_no_shared_mutable_default(self):
        s1 = Sample("a" * 64)
        s2 = Sample("b" * 64)
        s1.vmray_result["key"] = "value"
        assert "key" not in s2.vmray_result

    def test_no_shared_vtis_default(self):
        s1 = Sample("a" * 64)
        s2 = Sample("b" * 64)
        s1.vmray_vtis.append({"id": 1})
        assert s2.vmray_vtis == []

    def test_no_shared_metadata_default(self):
        s1 = Sample("a" * 64)
        s2 = Sample("b" * 64)
        s1.vmray_metadata["k"] = "v"
        assert "k" not in s2.vmray_metadata


class TestSampleStr:
    def test_str_contains_sha256(self):
        s = Sample(SHA256)
        assert SHA256 in str(s)

    def test_str_is_string(self):
        s = Sample(SHA256)
        assert isinstance(str(s), str)

    def test_str_includes_paths(self):
        s = Sample(SHA256)
        s.zipped_path = "/tmp/abc.zip"
        s.unzipped_path = "/tmp/abc"
        output = str(s)
        assert "/tmp/abc.zip" in output
        assert "/tmp/abc" in output
