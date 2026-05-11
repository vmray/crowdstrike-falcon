"""Tests for the VMRay wrapper class."""

from unittest.mock import MagicMock, patch, call

import pytest

from lib.VMRay import VMRay
from lib.Sample import Sample
from config.general_conf import VERDICT, GeneralConfig
from config.vmray_conf import VMRayConfig
from config.constants import VMRAY_JOB_STATUS_INWORK

SHA256 = "e" * 64


# ---------------------------------------------------------------------------
# __init__ / authenticate / healthcheck
# ---------------------------------------------------------------------------

class TestVMRayInit:
    def test_init_calls_authenticate_and_healthcheck(self, mocker):
        mock_auth = mocker.patch.object(VMRay, "authenticate")
        mock_hc = mocker.patch.object(VMRay, "healthcheck")
        VMRay()
        mock_auth.assert_called_once()
        mock_hc.assert_called_once()

    def test_authenticate_success(self, mocker):
        mock_api_cls = mocker.patch("lib.VMRay.VMRayRESTAPI")
        mocker.patch.object(VMRay, "healthcheck")
        instance = VMRay()
        assert instance.api is mock_api_cls.return_value

    def test_authenticate_failure_raises(self, mocker):
        mocker.patch("lib.VMRay.VMRayRESTAPI", side_effect=Exception("bad key"))
        mocker.patch.object(VMRay, "healthcheck")
        with pytest.raises(Exception, match="bad key"):
            VMRay()

    def test_healthcheck_success(self, mocker):
        mock_api = MagicMock()
        mock_api.call.return_value = {}

        def mock_authenticate(self):
            self.api = mock_api

        mocker.patch.object(VMRay, "authenticate", mock_authenticate)
        instance = VMRay()
        assert instance.api.call.called

    def test_healthcheck_failure_raises(self, mocker):
        mock_api = MagicMock()
        mock_api.call.side_effect = Exception("unreachable")

        def mock_authenticate(self):
            self.api = mock_api

        mocker.patch.object(VMRay, "authenticate", mock_authenticate)
        with pytest.raises(Exception, match="unreachable"):
            VMRay()


# ---------------------------------------------------------------------------
# get_sample_summary
# ---------------------------------------------------------------------------

class TestGetSampleSummary:
    def test_returns_dict_when_found(self, vmray_instance):
        vmray_instance.api.call.return_value = {"sample_id": 1, "sample_verdict": "malicious"}
        result = vmray_instance.get_sample_summary(SHA256)
        assert result == {"sample_id": 1, "sample_verdict": "malicious"}

    def test_returns_list_when_found_list(self, vmray_instance):
        vmray_instance.api.call.return_value = [{"sample_id": 1}]
        result = vmray_instance.get_sample_summary(SHA256)
        assert result == [{"sample_id": 1}]

    def test_returns_none_when_empty_list(self, vmray_instance):
        vmray_instance.api.call.return_value = []
        result = vmray_instance.get_sample_summary(SHA256)
        assert result is None

    def test_returns_none_when_none_response(self, vmray_instance):
        vmray_instance.api.call.return_value = None
        result = vmray_instance.get_sample_summary(SHA256)
        assert result is None

    def test_returns_none_on_exception(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("not found")
        result = vmray_instance.get_sample_summary(SHA256)
        assert result is None

    def test_uses_sample_id_endpoint(self, vmray_instance):
        vmray_instance.api.call.return_value = {"sample_id": 42}
        vmray_instance.get_sample_summary(42, sample_id=True)
        vmray_instance.api.call.assert_called_with("GET", "/rest/sample/42")

    def test_uses_sha256_endpoint_by_default(self, vmray_instance):
        vmray_instance.api.call.return_value = {"sample_id": 1}
        vmray_instance.get_sample_summary(SHA256)
        vmray_instance.api.call.assert_called_with("GET", f"/rest/sample/sha256/{SHA256}")


# ---------------------------------------------------------------------------
# get_sample_iocs
# ---------------------------------------------------------------------------

class TestGetSampleIocs:
    def test_returns_iocs_for_selected_verdicts(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        vmray_instance.api.call.return_value = {"iocs": {}}
        result = vmray_instance.get_sample_iocs({"sample_id": 1})
        assert "malicious" in result

    def test_skips_verdict_on_api_exception(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious", "suspicious"])
        vmray_instance.api.call.side_effect = Exception("error")
        result = vmray_instance.get_sample_iocs({"sample_id": 1})
        assert result == {}

    def test_skips_none_response(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        vmray_instance.api.call.return_value = None
        result = vmray_instance.get_sample_iocs({"sample_id": 1})
        assert result == {}


# ---------------------------------------------------------------------------
# get_sample_vtis / get_sample_threat_names / get_sample_classifications
# ---------------------------------------------------------------------------

class TestGetSampleExtras:
    def test_get_vtis_returns_response(self, vmray_instance):
        vmray_instance.api.call.return_value = {"threat_indicators": []}
        result = vmray_instance.get_sample_vtis(1)
        assert result == {"threat_indicators": []}

    def test_get_vtis_returns_none_on_exception(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("fail")
        assert vmray_instance.get_sample_vtis(1) is None

    def test_get_threat_names_returns_response(self, vmray_instance):
        vmray_instance.api.call.return_value = {"sample_threat_names": []}
        result = vmray_instance.get_sample_threat_names(1)
        assert result == {"sample_threat_names": []}

    def test_get_threat_names_returns_none_on_exception(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("fail")
        assert vmray_instance.get_sample_threat_names(1) is None

    def test_get_classifications_returns_response(self, vmray_instance):
        vmray_instance.api.call.return_value = {"sample_classifications": []}
        result = vmray_instance.get_sample_classifications(1)
        assert result == {"sample_classifications": []}

    def test_get_classifications_returns_none_on_exception(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("fail")
        assert vmray_instance.get_sample_classifications(1) is None


# ---------------------------------------------------------------------------
# parse_sample_vtis
# ---------------------------------------------------------------------------

class TestParseSampleVTIs:
    def test_returns_empty_on_none(self, vmray_instance):
        assert vmray_instance.parse_sample_vtis(None) == []

    def test_returns_empty_on_empty_dict(self, vmray_instance):
        assert vmray_instance.parse_sample_vtis({}) == []

    def test_returns_empty_when_no_threat_indicators(self, vmray_instance):
        assert vmray_instance.parse_sample_vtis({"threat_indicators": []}) == []

    def test_parses_indicator_fields(self, vmray_instance):
        raw = {
            "threat_indicators": [{
                "id": 1,
                "category": "Process",
                "operation": "Spawn child",
                "score": 9,
                "classifications": ["Trojan"],
            }]
        }
        result = vmray_instance.parse_sample_vtis(raw)
        assert len(result) == 1
        assert result[0]["id"] == 1
        assert result[0]["category"] == "Process"
        assert result[0]["operation"] == "Spawn child"
        assert result[0]["score"] == 9
        assert result[0]["classifications"] == ["Trojan"]

    def test_parses_multiple_indicators(self, vmray_instance):
        raw = {
            "threat_indicators": [
                {"id": 1, "category": "A", "operation": "op1", "score": 1, "classifications": []},
                {"id": 2, "category": "B", "operation": "op2", "score": 2, "classifications": []},
            ]
        }
        result = vmray_instance.parse_sample_vtis(raw)
        assert len(result) == 2

    def test_missing_optional_fields_default_to_none_or_empty(self, vmray_instance):
        raw = {"threat_indicators": [{"id": 10}]}
        result = vmray_instance.parse_sample_vtis(raw)
        assert result[0]["category"] is None
        assert result[0]["classifications"] == []


# ---------------------------------------------------------------------------
# parse_sample_threat_names
# ---------------------------------------------------------------------------

class TestParseSampleThreatNames:
    def test_returns_empty_set_on_none(self, vmray_instance):
        assert vmray_instance.parse_sample_threat_names(None) == set()

    def test_returns_empty_set_on_empty(self, vmray_instance):
        assert vmray_instance.parse_sample_threat_names({}) == set()

    def test_merges_sample_and_children(self, vmray_instance):
        raw = {
            "sample_threat_names": [{"threat_name": "TrojanA"}],
            "children_threat_names": [{"threat_name": "TrojanB"}],
        }
        result = vmray_instance.parse_sample_threat_names(raw)
        assert result == {"TrojanA", "TrojanB"}

    def test_handles_missing_children_key(self, vmray_instance):
        raw = {"sample_threat_names": [{"threat_name": "TrojanA"}]}
        result = vmray_instance.parse_sample_threat_names(raw)
        assert result == {"TrojanA"}

    def test_returns_set_type(self, vmray_instance):
        raw = {"sample_threat_names": [{"threat_name": "T"}]}
        assert isinstance(vmray_instance.parse_sample_threat_names(raw), set)

    def test_deduplicates_names(self, vmray_instance):
        raw = {
            "sample_threat_names": [{"threat_name": "Same"}],
            "children_threat_names": [{"threat_name": "Same"}],
        }
        result = vmray_instance.parse_sample_threat_names(raw)
        assert result == {"Same"}

    def test_filters_none_threat_names(self, vmray_instance):
        raw = {"sample_threat_names": [{"threat_name": None}, {"threat_name": "Trojan"}]}
        result = vmray_instance.parse_sample_threat_names(raw)
        assert None not in result
        assert "Trojan" in result


# ---------------------------------------------------------------------------
# parse_sample_classifications
# ---------------------------------------------------------------------------

class TestParseSampleClassifications:
    def test_returns_empty_set_on_none(self, vmray_instance):
        assert vmray_instance.parse_sample_classifications(None) == set()

    def test_merges_sample_and_children(self, vmray_instance):
        raw = {
            "sample_classifications": [{"classification_name": "Dropper"}],
            "children_classifications": [{"classification_name": "Spyware"}],
        }
        result = vmray_instance.parse_sample_classifications(raw)
        assert result == {"Dropper", "Spyware"}

    def test_handles_none_values_in_list(self, vmray_instance):
        raw = {"sample_classifications": [{"classification_name": None}, {"classification_name": "Trojan"}]}
        result = vmray_instance.parse_sample_classifications(raw)
        assert None not in result
        assert "Trojan" in result


# ---------------------------------------------------------------------------
# parse_sample_summary_data
# ---------------------------------------------------------------------------

class TestParseSampleSummaryData:
    def test_extracts_known_keys(self, vmray_instance):
        raw = {
            "sample_id": 42,
            "sample_verdict": "malicious",
            "sample_vti_score": 100,
            "sample_webif_url": "https://example.com",
            "irrelevant_key": "ignored",
        }
        result = vmray_instance.parse_sample_summary_data(raw)
        assert result["sample_id"] == 42
        assert result["sample_verdict"] == "malicious"
        assert result["sample_vti_score"] == 100
        assert result["sample_webif_url"] == "https://example.com"
        assert "irrelevant_key" not in result

    def test_handles_list_input_uses_first_element(self, vmray_instance):
        raw = [{"sample_id": 1, "sample_verdict": "clean"}, {"sample_id": 2}]
        result = vmray_instance.parse_sample_summary_data(raw)
        assert result["sample_id"] == 1

    def test_handles_none_input(self, vmray_instance):
        result = vmray_instance.parse_sample_summary_data(None)
        assert result == {}

    def test_partial_keys_only_present_keys_returned(self, vmray_instance):
        raw = {"sample_id": 5}
        result = vmray_instance.parse_sample_summary_data(raw)
        assert result == {"sample_id": 5}

    def test_empty_dict_returns_empty(self, vmray_instance):
        assert vmray_instance.parse_sample_summary_data({}) == {}


# ---------------------------------------------------------------------------
# parse_process_iocs
# ---------------------------------------------------------------------------

class TestParseProcessIOCs:
    def _make_iocs(self, processes, verdict_key="malicious"):
        return {
            verdict_key: {
                "iocs": {
                    "processes": processes,
                    "files": [],
                    "registry": [],
                    "ips": [],
                    "urls": [],
                }
            }
        }

    def test_extracts_cmd_line_and_image_names(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "malicious",
            "cmd_line": "cmd.exe /c malware",
            "image_names": ["C:\\Windows\\System32\\cmd.exe"],
        }])
        result = vmray_instance.parse_process_iocs(iocs)
        assert "cmd.exe /c malware" in result["cmdline"]
        assert "C:\\Windows\\System32\\cmd.exe" in result["image_name"]

    def test_skips_non_selected_verdict(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "clean",
            "cmd_line": "legitimate.exe",
            "image_names": [],
        }])
        result = vmray_instance.parse_process_iocs(iocs)
        assert "legitimate.exe" not in result["cmdline"]

    def test_handles_none_image_names(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "malicious",
            "cmd_line": "cmd",
            "image_names": None,
        }])
        result = vmray_instance.parse_process_iocs(iocs)
        assert result["image_name"] == set()


# ---------------------------------------------------------------------------
# parse_file_iocs
# ---------------------------------------------------------------------------

class TestParseFileIOCs:
    def _make_iocs(self, files, verdict_key="malicious"):
        return {
            verdict_key: {
                "iocs": {
                    "processes": [],
                    "files": files,
                    "registry": [],
                    "ips": [],
                    "urls": [],
                }
            }
        }

    def test_extracts_sha256_and_filename(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "malicious",
            "classifications": [],
            "hashes": [{"sha256_hash": "f" * 64}],
            "filenames": ["malware.exe"],
        }])
        result = vmray_instance.parse_file_iocs(iocs)
        assert "f" * 64 in result["sha256"]
        assert "malware.exe" in result["file_name"]

    def test_skips_ransomware_classification(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "malicious",
            "classifications": ["Ransomware"],
            "hashes": [{"sha256_hash": "g" * 64}],
            "filenames": ["ransom.exe"],
        }])
        result = vmray_instance.parse_file_iocs(iocs)
        assert "g" * 64 not in result["sha256"]

    def test_handles_none_filenames(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "malicious",
            "classifications": [],
            "hashes": [{"sha256_hash": "h" * 64}],
            "filenames": None,
        }])
        result = vmray_instance.parse_file_iocs(iocs)
        assert result["file_name"] == set()

    def test_skips_non_selected_verdict(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "suspicious",
            "classifications": [],
            "hashes": [{"sha256_hash": "i" * 64}],
            "filenames": [],
        }])
        result = vmray_instance.parse_file_iocs(iocs)
        assert "i" * 64 not in result["sha256"]


# ---------------------------------------------------------------------------
# parse_registry_iocs
# ---------------------------------------------------------------------------

class TestParseRegistryIOCs:
    def _make_iocs(self, registry, verdict_key="malicious"):
        return {
            verdict_key: {
                "iocs": {
                    "processes": [],
                    "files": [],
                    "registry": registry,
                    "ips": [],
                    "urls": [],
                }
            }
        }

    def test_extracts_reg_key(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "malicious",
            "reg_key_name": "HKLM\\SOFTWARE\\malware",
        }])
        result = vmray_instance.parse_registry_iocs(iocs)
        assert "HKLM\\SOFTWARE\\malware" in result["reg_key"]

    def test_skips_missing_reg_key_name(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{"verdict": "malicious"}])
        result = vmray_instance.parse_registry_iocs(iocs)
        assert result["reg_key"] == set()

    def test_skips_non_selected_verdict(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs([{
            "verdict": "clean",
            "reg_key_name": "HKCU\\legit",
        }])
        result = vmray_instance.parse_registry_iocs(iocs)
        assert "HKCU\\legit" not in result["reg_key"]


# ---------------------------------------------------------------------------
# parse_network_iocs
# ---------------------------------------------------------------------------

class TestParseNetworkIOCs:
    def _make_iocs(self, ips=None, urls=None, verdict_key="malicious"):
        return {
            verdict_key: {
                "iocs": {
                    "processes": [],
                    "files": [],
                    "registry": [],
                    "ips": ips or [],
                    "urls": urls or [],
                }
            }
        }

    def test_extracts_domain_from_ip_entry(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(ips=[{
            "verdict": "malicious",
            "ip_address": "1.2.3.4",
            "domains": ["evil.example.com"],
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert "1.2.3.4" in result["ipv4"]
        assert "evil.example.com" in result["domain"]

    def test_extracts_ip_from_url_entry(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(urls=[{
            "verdict": "malicious",
            "ip_addresses": ["5.6.7.8"],
            "original_urls": [],
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert "5.6.7.8" in result["ipv4"]

    def test_url_netloc_ip_goes_to_ipv4(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(urls=[{
            "verdict": "malicious",
            "ip_addresses": [],
            "original_urls": ["http://192.168.0.1/path"],
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert "192.168.0.1" in result["ipv4"]
        assert len(result["domain"]) == 0

    def test_url_netloc_domain_goes_to_domain(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(urls=[{
            "verdict": "malicious",
            "ip_addresses": [],
            "original_urls": ["https://evil.test.com/download"],
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert "evil.test.com" in result["domain"]
        assert "evil.test.com" not in result["ipv4"]

    def test_url_with_empty_netloc_skipped(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(urls=[{
            "verdict": "malicious",
            "ip_addresses": [],
            "original_urls": ["not_a_valid_url"],
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert result["domain"] == set()
        assert result["ipv4"] == set()

    def test_skips_non_selected_verdict(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(ips=[{
            "verdict": "clean",
            "ip_address": "10.0.0.1",
            "domains": ["legit.com"],
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert "10.0.0.1" not in result["ipv4"]

    def test_handles_none_domains_in_ip_entry(self, vmray_instance, mocker):
        mocker.patch.object(GeneralConfig, "SELECTED_VERDICTS", ["malicious"])
        iocs = self._make_iocs(ips=[{
            "verdict": "malicious",
            "ip_address": "1.2.3.4",
            "domains": None,
        }])
        result = vmray_instance.parse_network_iocs(iocs)
        assert result["domain"] == set()


# ---------------------------------------------------------------------------
# submit_sample
# ---------------------------------------------------------------------------

class TestSubmitSample:
    def test_success_sets_submission_id_and_sample_id(self, vmray_instance, tmp_path):
        unzipped = tmp_path / ("s" * 64)
        unzipped.write_bytes(b"content")
        sample = Sample("s" * 64)
        sample.unzipped_path = unzipped

        vmray_instance.api.call.return_value = {
            "errors": [],
            "submissions": [{"submission_id": 99, "sample_id": 42}],
        }
        vmray_instance.submit_sample(sample)

        assert sample.vmray_submit_successfully is True
        assert sample.vmray_submission_id == 99
        assert sample.vmray_sample_id == 42

    def test_api_exception_sets_not_submitted(self, vmray_instance, tmp_path):
        unzipped = tmp_path / ("t" * 64)
        unzipped.write_bytes(b"content")
        sample = Sample("t" * 64)
        sample.unzipped_path = unzipped

        vmray_instance.api.call.side_effect = Exception("upload failed")
        vmray_instance.submit_sample(sample)

        assert sample.vmray_submit_successfully is False
        assert sample.vmray_submission_id is None

    def test_api_returns_errors_sets_not_submitted(self, vmray_instance, tmp_path):
        unzipped = tmp_path / ("u" * 64)
        unzipped.write_bytes(b"content")
        sample = Sample("u" * 64)
        sample.unzipped_path = unzipped

        vmray_instance.api.call.return_value = {
            "errors": [{"code": "ERR_FILE_TOO_LARGE"}],
            "submissions": [],
        }
        vmray_instance.submit_sample(sample)

        assert sample.vmray_submit_successfully is False

    def test_no_submissions_in_response_sets_not_submitted(self, vmray_instance, tmp_path):
        unzipped = tmp_path / ("v" * 64)
        unzipped.write_bytes(b"content")
        sample = Sample("v" * 64)
        sample.unzipped_path = unzipped

        vmray_instance.api.call.return_value = {"errors": [], "submissions": []}
        vmray_instance.submit_sample(sample)

        assert sample.vmray_submit_successfully is False

    def test_submission_without_sample_id_still_succeeds(self, vmray_instance, tmp_path):
        unzipped = tmp_path / ("w" * 64)
        unzipped.write_bytes(b"content")
        sample = Sample("w" * 64)
        sample.unzipped_path = unzipped

        vmray_instance.api.call.return_value = {
            "errors": [],
            "submissions": [{"submission_id": 10}],
        }
        vmray_instance.submit_sample(sample)

        assert sample.vmray_submit_successfully is True
        assert sample.vmray_submission_id == 10

    def test_file_open_failure_sets_not_submitted(self, vmray_instance, mocker):
        mocker.patch("io.open", side_effect=IOError("file missing"))
        sample = Sample("x" * 64)
        sample.unzipped_path = "/nonexistent/path"
        vmray_instance.submit_sample(sample)
        assert sample.vmray_submit_successfully is False


# ---------------------------------------------------------------------------
# is_submission_started
# ---------------------------------------------------------------------------

class TestIsSubmissionStarted:
    def test_returns_true_when_inwork_job(self, vmray_instance):
        vmray_instance.api.call.return_value = [{"job_status": VMRAY_JOB_STATUS_INWORK}]
        assert vmray_instance.is_submission_started(1) is True

    def test_returns_false_when_no_inwork_job(self, vmray_instance):
        vmray_instance.api.call.return_value = [{"job_status": "queued"}]
        assert vmray_instance.is_submission_started(1) is False

    def test_returns_false_on_empty_list(self, vmray_instance):
        vmray_instance.api.call.return_value = []
        assert vmray_instance.is_submission_started(1) is False

    def test_returns_false_on_exception(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("error")
        assert vmray_instance.is_submission_started(1) is False


# ---------------------------------------------------------------------------
# get_submission_analyses / check_submission_error
# ---------------------------------------------------------------------------

class TestGetSubmissionAnalyses:
    def test_returns_analyses(self, vmray_instance):
        vmray_instance.api.call.return_value = [{"analysis_id": 1, "analysis_verdict": "ok"}]
        result = vmray_instance.get_submission_analyses(1)
        assert result == [{"analysis_id": 1, "analysis_verdict": "ok"}]

    def test_returns_none_on_exception(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("fail")
        assert vmray_instance.get_submission_analyses(1) is None


class TestCheckSubmissionError:
    def test_returns_false_when_all_clean(self, vmray_instance):
        vmray_instance.api.call.return_value = [
            {"analysis_id": 1, "analysis_verdict": "malicious", "analysis_result_str": "ok"}
        ]
        assert vmray_instance.check_submission_error(1) is False

    def test_returns_true_when_analysis_verdict_error(self, vmray_instance):
        vmray_instance.api.call.return_value = [
            {"analysis_id": 1, "analysis_verdict": "error", "analysis_result_str": "crashed"}
        ]
        assert vmray_instance.check_submission_error(1) is True

    def test_returns_true_when_analyses_none(self, vmray_instance):
        vmray_instance.api.call.side_effect = Exception("fail")
        assert vmray_instance.check_submission_error(1) is True


# ---------------------------------------------------------------------------
# wait_submissions
# ---------------------------------------------------------------------------

class TestWaitSubmissions:
    def test_skips_not_downloaded_samples(self, vmray_instance):
        sample = Sample(SHA256)
        sample.downloaded_successfully = False
        sample.vmray_submit_successfully = True
        vmray_instance.wait_submissions([sample])
        vmray_instance.api.call.assert_not_called()

    def test_skips_not_submitted_samples(self, vmray_instance):
        sample = Sample(SHA256)
        sample.downloaded_successfully = True
        sample.vmray_submit_successfully = False
        vmray_instance.wait_submissions([sample])
        vmray_instance.api.call.assert_not_called()

    def test_empty_list_does_nothing(self, vmray_instance):
        vmray_instance.wait_submissions([])
        vmray_instance.api.call.assert_not_called()

    def test_finished_submission_calls_add_sample_results(self, vmray_instance, mocker):
        mocker.patch.object(VMRayConfig, "POLL_INTERVAL", 0)
        mocker.patch("lib.VMRay.time.sleep")
        mocker.patch.object(vmray_instance, "check_submission_error", return_value=False)
        mocker.patch.object(vmray_instance, "add_sample_results")

        sample = Sample(SHA256)
        sample.downloaded_successfully = True
        sample.vmray_submit_successfully = True
        sample.vmray_submission_id = 1

        vmray_instance.api.call.return_value = {"submission_finished": True}

        vmray_instance.wait_submissions([sample])

        assert sample.vmray_submission_finished is True
        vmray_instance.add_sample_results.assert_called_once_with(sample)

    def test_submission_error_raises_and_marks_unfinished(self, vmray_instance, mocker):
        mocker.patch.object(VMRayConfig, "POLL_INTERVAL", 0)
        mocker.patch("lib.VMRay.time.sleep")
        mocker.patch.object(vmray_instance, "check_submission_error", return_value=True)

        sample = Sample(SHA256)
        sample.downloaded_successfully = True
        sample.vmray_submit_successfully = True
        sample.vmray_submission_id = 1

        vmray_instance.api.call.return_value = {"submission_finished": True}

        vmray_instance.wait_submissions([sample])
        assert sample.vmray_submission_finished is False

    def test_max_consecutive_errors_marks_unfinished(self, vmray_instance, mocker):
        mocker.patch.object(VMRayConfig, "POLL_INTERVAL", 0)
        mocker.patch("lib.VMRay.time.sleep")

        sample = Sample(SHA256)
        sample.downloaded_successfully = True
        sample.vmray_submit_successfully = True
        sample.vmray_submission_id = 1

        vmray_instance.api.call.side_effect = Exception("network error")

        vmray_instance.wait_submissions([sample])

        assert sample.vmray_submission_finished is False
        assert vmray_instance.api.call.call_count == 6

    def test_timeout_marks_unfinished(self, vmray_instance, mocker):
        mocker.patch.object(VMRayConfig, "POLL_INTERVAL", 0)
        mocker.patch.object(VMRayConfig, "ANALYSIS_JOB_TIMEOUT", 0)
        mocker.patch("lib.VMRay.time.sleep")
        mocker.patch.object(vmray_instance, "is_submission_started", return_value=True)

        sample = Sample(SHA256)
        sample.downloaded_successfully = True
        sample.vmray_submit_successfully = True
        sample.vmray_submission_id = 1

        vmray_instance.api.call.return_value = {"submission_finished": False}

        vmray_instance.wait_submissions([sample])
        assert sample.vmray_submission_finished is False


# ---------------------------------------------------------------------------
# add_sample_results
# ---------------------------------------------------------------------------

class TestAddSampleResults:
    def _setup(self, vmray_instance, mocker, verdict_str="malicious"):
        summary = {"sample_id": 10, "sample_verdict": verdict_str, "sample_webif_url": "https://x"}
        mocker.patch.object(vmray_instance, "get_sample_summary", return_value=summary)
        mocker.patch.object(vmray_instance, "parse_sample_summary_data", return_value=summary)
        mocker.patch.object(vmray_instance, "get_sample_iocs", return_value={})
        mocker.patch.object(vmray_instance, "parse_sample_iocs", return_value={
            "sha256": set(), "ipv4": set(), "domain": set()
        })
        mocker.patch.object(vmray_instance, "get_sample_vtis", return_value=None)
        mocker.patch.object(vmray_instance, "parse_sample_vtis", return_value=[])
        mocker.patch.object(vmray_instance, "get_sample_threat_names", return_value=None)
        mocker.patch.object(vmray_instance, "parse_sample_threat_names", return_value=set())
        mocker.patch.object(vmray_instance, "get_sample_classifications", return_value=None)
        mocker.patch.object(vmray_instance, "parse_sample_classifications", return_value=set())

    def test_sets_malicious_verdict(self, vmray_instance, mocker):
        self._setup(vmray_instance, mocker, verdict_str="malicious")
        sample = Sample(SHA256)
        vmray_instance.add_sample_results(sample)
        assert sample.vmray_verdict == VERDICT.MALICIOUS

    def test_sets_suspicious_verdict(self, vmray_instance, mocker):
        self._setup(vmray_instance, mocker, verdict_str="suspicious")
        sample = Sample(SHA256)
        vmray_instance.add_sample_results(sample)
        assert sample.vmray_verdict == VERDICT.SUSPICIOUS

    def test_sets_clean_verdict_for_unknown(self, vmray_instance, mocker):
        self._setup(vmray_instance, mocker, verdict_str="clean")
        sample = Sample(SHA256)
        vmray_instance.add_sample_results(sample)
        assert sample.vmray_verdict == VERDICT.CLEAN

    def test_populates_metadata(self, vmray_instance, mocker):
        self._setup(vmray_instance, mocker)
        sample = Sample(SHA256)
        vmray_instance.add_sample_results(sample)
        assert sample.vmray_metadata != {}

    def test_returns_early_when_summary_none(self, vmray_instance, mocker):
        mocker.patch.object(vmray_instance, "get_sample_summary", return_value=None)
        sample = Sample(SHA256)
        vmray_instance.add_sample_results(sample)
        assert sample.vmray_metadata == {}
