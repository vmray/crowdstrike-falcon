"""VMRay REST API wrapper for sample submission, polling, and IOC/VTI retrieval."""

import logging
import time
import ipaddress
from datetime import datetime

from urllib.parse import urlparse
import json
import io

from vmray.rest_api import VMRayRESTAPI

from config.general_conf import GeneralConfig, VERDICT
from config.vmray_conf import VMRayConfig
from config.constants import VMRAY_JOB_STATUS_INWORK
from lib.Sample import Sample

logger = logging.getLogger(__name__)


class VMRay:
    """Wrapper around the VMRay REST API SDK used by the connector.

    Authenticates and health-checks the API on construction, then exposes
    methods for sample submission, polling, and result parsing.

    Attributes:
        api (VMRayRESTAPI): Authenticated VMRay REST API client.
        config (VMRayConfig): Configuration class used by all API calls.
    """

    def __init__(self):
        self.api = None
        self.config = VMRayConfig

        self.authenticate()
        self.healthcheck()

    def healthcheck(self):
        """Verify the VMRay REST API is reachable via ``GET /rest/system_info``.

        Returns:
            bool: ``True`` if the health check passes.

        Raises:
            Exception: If the API call fails (propagated from the SDK).
        """
        try:
            self.api.call("GET", "/rest/system_info")
            logger.info("VMRay health check succeeded.")
            return True
        except Exception as err:
            logger.error(f"VMRay health check failed: {err}")
            raise

    def authenticate(self):
        """Authenticate against the VMRay REST API using the configured API key.

        Raises:
            Exception: If the VMRay SDK raises during client construction.
        """
        try:
            self.api = VMRayRESTAPI(self.config.URL, self.config.API_KEY,
                                    self.config.SSL_VERIFY, self.config.CONNECTOR_NAME)
            logger.info(f"VMRay API authenticated ({self.config.API_KEY_TYPE} key)")
        except Exception as err:
            logger.error(f"VMRay authentication failed: {err}")
            raise

    def get_sample_summary(self, identifier, sample_id=False):
        """Retrieve a sample summary from VMRay by SHA-256 hash or sample ID.

        Args:
            identifier (str): SHA-256 hash or numeric sample ID of the sample.
            sample_id (bool, optional): When ``True``, treat ``identifier`` as a
                VMRay sample ID and query ``/rest/sample/{id}``. When ``False``
                (default), query ``/rest/sample/sha256/{hash}``.

        Returns:
            dict | None: Raw VMRay sample summary, or ``None`` if the
                sample was not found or an error occurred.
        """
        method = "GET"
        url = f"/rest/sample/{identifier}" if sample_id else f"/rest/sample/sha256/{identifier}"
        try:
            response = self.api.call(method, url)
            if not response or (isinstance(response, list) and len(response) == 0):
                logger.debug(f"Sample {identifier} not found in VMRay database")
                return None
            logger.debug(f"Sample {identifier} found in VMRay database")
            return response
        except Exception as err:
            logger.warning(f"Failed to retrieve sample summary for {identifier}: {err}")
            return None

    def get_sample_iocs(self, sample_data):
        """Retrieve IOC data from VMRay for the configured verdict types.

        Args:
            sample_data (dict): Parsed sample metadata

        Returns:
            dict: Mapping of verdict string to the raw IOC response for that
                verdict. Empty if no IOCs were returned.
        """
        sample_id = sample_data["sample_id"]
        iocs = {}

        if not GeneralConfig.SELECTED_VERDICTS:
            logger.warning("SELECTED_VERDICTS is empty. Configure it in general_conf.py to enable IOC retrieval.")
            return iocs

        for key in GeneralConfig.SELECTED_VERDICTS:
            try:
                response = self.api.call("GET", f"/rest/sample/{sample_id}/iocs/verdict/{key}")
                if response is not None:
                    iocs[key] = response
            except Exception as err:
                logger.error(f"Failed to retrieve IOCs for sample {sample_id}: {err}")

        return iocs

    def get_sample_vtis(self, sample_id):
        """Retrieve VTI (VMRay Threat Identifier) entries for a sample.

        Args:
            sample_id (int | str): VMRay sample ID.

        Returns:
            dict | None: Raw VTI response dict (with ``threat_indicators`` key),
                or ``None`` if retrieval fails.
        """
        try:
            response = self.api.call("GET", f"/rest/sample/{sample_id}/vtis")
            logger.debug(f"Retrieved VTIs for sample {sample_id}")
            return response
        except Exception as err:
            logger.warning(f"Could not retrieve VTIs for sample {sample_id}: {err}")
            return None

    def get_sample_threat_names(self, sample_id):
        """Retrieve threat names for a sample from the dedicated endpoint.

        Args:
            sample_id (int | str): VMRay sample ID.

        Returns:
            dict | None: Response containing ``sample_threat_names`` and
                ``children_threat_names``, or ``None`` if retrieval fails.
        """
        try:
            response = self.api.call("GET", f"/rest/sample/{sample_id}/threat_names")
            logger.debug(f"Retrieved threat names for sample {sample_id}")
            return response
        except Exception as err:
            logger.warning(f"Could not retrieve threat names for sample {sample_id}: {err}")
            return None

    def get_sample_classifications(self, sample_id):
        """Retrieve classifications for a sample from the dedicated endpoint.

        Args:
            sample_id (int | str): VMRay sample ID.

        Returns:
            dict | None: Response containing ``sample_classifications`` and
                ``children_classifications``, or ``None`` if retrieval fails.
        """
        try:
            response = self.api.call("GET", f"/rest/sample/{sample_id}/classifications")
            logger.debug(f"Retrieved classifications for sample {sample_id}")
            return response
        except Exception as err:
            logger.warning(f"Could not retrieve classifications for sample {sample_id}: {err}")
            return None

    def parse_sample_vtis(self, vtis):
        """Parse raw VTI response into a list of structured threat indicator dicts.

        Args:
            vtis (dict | None): Raw response from :meth:`get_sample_vtis`.

        Returns:
            list[dict]: Each dict contains ``id``, ``category``, ``operation``,
                ``score``, and ``classifications``. Empty list if input is falsy
                or contains no ``threat_indicators``.
        """
        if not vtis:
            return []

        indicators = vtis.get("threat_indicators", [])
        parsed = []
        for indicator in indicators:
            parsed.append({
                "id": indicator.get("id"),
                "category": indicator.get("category"),
                "operation": indicator.get("operation"),
                "score": indicator.get("score"),
                "classifications": indicator.get("classifications", []),
            })
        return parsed

    def parse_sample_threat_names(self, response):
        """Parse the response from ``GET /rest/sample/<id>/threat_names``.

        Merges ``sample_threat_names`` and ``children_threat_names`` into one set.

        Args:
            response (dict | None): Raw response from :meth:`get_sample_threat_names`.

        Returns:
            set[str]: All threat names from the sample and its children.
        """
        threat_names = set()
        if not response:
            return threat_names
        for key in ("sample_threat_names", "children_threat_names"):
            for threat_name_obj in (response.get(key) or []):
                name = threat_name_obj.get("threat_name")
                if name is not None:
                    threat_names.add(name)
        return threat_names

    def parse_sample_classifications(self, response):
        """Parse the response from ``GET /rest/sample/<id>/classifications``.

        Merges ``sample_classifications`` and ``children_classifications`` into one set.

        Args:
            response (dict | None): Raw response from :meth:`get_sample_classifications`.

        Returns:
            set[str]: All classifications from the sample and its children.
        """
        classifications = set()
        if not response:
            return classifications
        for key in ("sample_classifications", "children_classifications"):
            for classification_obj in (response.get(key) or []):
                name = classification_obj.get("classification_name")
                if name is not None:
                    classifications.add(name)
        return classifications

    def parse_sample_summary_data(self, sample_summary):
        """Extract a fixed set of fields from a raw VMRay sample summary response.

        Args:
            sample_summary (dict | list): Raw response from the VMRay sample
                summary endpoint.

        Returns:
            dict: Flat dict containing whichever of the expected keys were present
                in the summary (e.g. ``sample_id``, ``sample_verdict``,
                ``sample_vti_score``, ``sample_webif_url``).
        """
        sample_data = {}
        keys = [
            "sample_id",
            "sample_verdict",
            "sample_vti_score",
            "sample_severity",
            "sample_child_sample_ids",
            "sample_parent_sample_ids",
            "sample_md5hash",
            "sample_sha256hash",
            "sample_webif_url",
        ]
        if sample_summary is not None:
            if isinstance(sample_summary, list):
                sample_summary = sample_summary[0]
            for key in keys:
                if key in sample_summary:
                    sample_data[key] = sample_summary[key]
        return sample_data

    def parse_sample_iocs(self, iocs):
        """Parse and merge all IOC categories into a single flat dict.

        Args:
            iocs (dict): Raw IOC data

        Returns:
            dict: Merged IOC dict with keys ``cmdline``, ``image_name``,
                ``sha256``, ``file_name``, ``domain``, ``ipv4``, ``reg_key``,
                ``classifications``, and ``threat_names`` (each a ``set``).
        """
        ioc_data = {}

        for parser in (
            self.parse_process_iocs,
            self.parse_file_iocs,
            self.parse_network_iocs,
            self.parse_registry_iocs,
        ):
            ioc_data.update(parser(iocs))

        return ioc_data

    def parse_process_iocs(self, iocs):
        """Extract process IOCs from the raw IOC dict.

        Args:
            iocs (dict): Raw IOC data
        Returns:
            dict: ``{"cmdline": set[str], "image_name": set[str]}``.
        """
        cmd_lines = set()
        image_names = set()
    
        if not GeneralConfig.SELECTED_VERDICTS:
            logger.warning("No process IOCs parsed. Configure SELECTED_VERDICTS in general_conf.py to parse process IOCs.")
            return {"cmdline": cmd_lines, "image_name": image_names}

        for ioc_type in iocs:
            for process in iocs[ioc_type]["iocs"]["processes"]:
                if process.get("verdict") in GeneralConfig.SELECTED_VERDICTS:
                    cmd_lines.add(process.get("cmd_line", ""))
                    image_names.update(process.get("image_names") or [])

        return {"cmdline": cmd_lines, "image_name": image_names}

    def parse_file_iocs(self, iocs):
        """Extract file IOCs from the raw IOC dict.

        Args:
            iocs (dict): Raw IOC data

        Returns:
            dict: ``{"sha256": set[str], "file_name": set[str]}``.
        """
        sha256 = set()
        filenames = set()

        if not GeneralConfig.SELECTED_VERDICTS:
            logger.warning("No file IOCs parsed. Configure SELECTED_VERDICTS in general_conf.py to parse file IOCs.")
            return {"sha256": sha256, "file_name": filenames}

        for ioc_type in iocs:
            for file in iocs[ioc_type]["iocs"]["files"]:
                if file["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    if "Ransomware" not in file["classifications"]:
                        for file_hash in file["hashes"]:
                            sha256.add(file_hash["sha256_hash"])
                        if file["filenames"] is not None:
                            filenames.update(file["filenames"])

        return {"sha256": sha256, "file_name": filenames}

    def parse_registry_iocs(self, iocs):
        """Extract registry IOCs from the raw IOC dict.

        Args:
            iocs (dict): Raw IOC data

        Returns:
            dict: ``{"reg_key": set[str]}``.
        """
        registry_keys = set()

        if not GeneralConfig.SELECTED_VERDICTS:
            logger.warning("No registry IOCs parsed. Configure SELECTED_VERDICTS in general_conf.py to parse registry IOCs.")
            return {"reg_key": registry_keys}

        for ioc_type in iocs:
            for reg in iocs[ioc_type]["iocs"]["registry"]:
                if reg["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    if "reg_key_name" in reg:
                        registry_keys.add(reg["reg_key_name"])

        return {"reg_key": registry_keys}

    def parse_network_iocs(self, iocs):
        """Extract network IOCs from the raw IOC dict.

        Args:
            iocs (dict): Raw IOC data

        Returns:
            dict: ``{"domain": set[str], "ipv4": set[str]}``.
        """
        domains = set()
        ip_addresses = set()

        if not GeneralConfig.SELECTED_VERDICTS:
            logger.warning("No network IOCs parsed. Configure SELECTED_VERDICTS in general_conf.py to parse network IOCs.")
            return {"domain": domains, "ipv4": ip_addresses}

        for ioc_type in iocs:
            for ip in iocs[ioc_type]["iocs"]["ips"]:
                if ip["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    domains.update(ip.get("domains") or [])
                    ip_addresses.add(ip["ip_address"])

            for url in iocs[ioc_type]["iocs"]["urls"]:
                if url["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    ip_addresses.update(url.get("ip_addresses") or [])
                    for original_url in (url.get("original_urls") or []):
                        netloc = urlparse(original_url).netloc
                        if not netloc:
                            continue
                        try:
                            ipaddress.ip_address(netloc)
                            ip_addresses.add(netloc)
                        except Exception:
                            domains.add(netloc)

        return {"domain": domains, "ipv4": ip_addresses}

    def submit_sample(self, sample: Sample):
        """Submit a sample file to VMRay Sandbox for analysis.

        Args:
            sample (Sample): Sample object
        """
        method = "POST"
        url = "/rest/sample/submit"

        params = {
            "comment": self.config.SUBMISSION_COMMENT,
            "tags": ",".join(self.config.SUBMISSION_TAGS),
            "user_config": json.dumps({"timeout": self.config.ANALYSIS_TIMEOUT}),
        }

        try:
            with io.open(sample.unzipped_path, "rb") as file_object:
                params["sample_file"] = file_object
                try:
                    response = self.api.call(method, url, params=params)
                except Exception as err:
                    logger.error(f"Failed to submit sample {sample.sample_sha256} to VMRay: {err}")
                    sample.vmray_submit_successfully = False
                    sample.vmray_submission_id = None
                    sample.vmray_sample_id = None
                    return

                if len(response.get("errors") or []) > 0:
                    sample.vmray_submit_successfully = False
                    for error in response["errors"]:
                        logger.error(f"VMRay submission error for {sample.sample_sha256}: {error}")
                    return

                if not response.get("submissions"):
                    logger.warning(f"VMRay returned no submission info for sample {sample.sample_sha256}")
                    sample.vmray_submit_successfully = False
                    return

                sample.vmray_submission_id = response["submissions"][0]["submission_id"]
                if "sample_id" in response["submissions"][0]:
                    sample.vmray_sample_id = response["submissions"][0]["sample_id"]
                sample.vmray_submit_successfully = True
                logger.info(f"Sample {sample.sample_sha256} submitted to VMRay (submission_id={sample.vmray_submission_id})")
        except Exception as err:
            logger.error(f"Failed to submit sample {sample.sample_sha256} to VMRay: {err}")
            sample.vmray_submit_successfully = False
            sample.vmray_submission_id = None
            sample.vmray_sample_id = None

    def wait_submissions(self, submitted_samples: list[Sample]):
        """Poll VMRay until all submitted samples finish analysis or time out.

        Args:
            submitted_samples (list[Sample]): Samples to monitor
        """
        submission_objects = []
        for submission in submitted_samples:
            if submission.downloaded_successfully and submission.vmray_submit_successfully:
                submission_objects.append({
                    "sample": submission,
                    "timestamp": None,
                    "consecutive_error_count": 0,
                })

        if not submission_objects:
            logger.info("No VMRay submissions to process.")
            return

        logger.info(f"Waiting for {len(submission_objects)} VMRay submission(s) to complete")

        while submission_objects:
            logger.info(f"{len(submission_objects)} submission(s) still pending")
            for submission_object in list(submission_objects):
                sub_id = submission_object["sample"].vmray_submission_id
                sha256 = submission_object["sample"].sample_sha256
                try:
                    response = self.api.call("GET", f"/rest/submission/{sub_id}")

                    if response["submission_finished"]:
                        if self.check_submission_error(sub_id):
                            raise Exception(
                                f"Analysis error detected for submission {sub_id}"
                            )
                        self.add_sample_results(submission_object["sample"])
                        submission_object["sample"].vmray_submission_finished = True
                        submission_objects.remove(submission_object)
                        logger.info(f"Submission {sub_id} finished for sample {sha256}")

                    elif submission_object["timestamp"] is None:
                        if self.is_submission_started(sub_id):
                            submission_object["timestamp"] = datetime.now()

                    elif (datetime.now() - submission_object["timestamp"]).total_seconds() >= VMRayConfig.ANALYSIS_JOB_TIMEOUT:
                        logger.warning(f"Submission {sub_id} exceeded the configured timeout ({VMRayConfig.ANALYSIS_JOB_TIMEOUT}s)")
                        submission_object["sample"].vmray_submission_finished = False
                        submission_objects.remove(submission_object)

                except Exception as err:
                    if submission_object["consecutive_error_count"] >= 5:
                        submission_object["sample"].vmray_submission_finished = False
                        submission_objects.remove(submission_object)
                        logger.warning(f"Submission {sub_id} abandoned after 5 consecutive errors")
                    else:
                        submission_object["consecutive_error_count"] += 1
                        logger.warning(f"Error occurred while waiting for submission {sub_id}: {err}. Retrying...")

            if submission_objects:
                time.sleep(VMRayConfig.POLL_INTERVAL)

        logger.info("All VMRay submissions have been processed")

    def is_submission_started(self, submission_id):
        """Check whether at least one analysis job is actively running for a submission.

        Args:
            submission_id (int | str): VMRay submission ID to check.

        Returns:
            bool: ``True`` if any job has status *inwork*, ``False`` otherwise or
                if the job list cannot be retrieved.
        """
        try:
            response = self.api.call("GET", f"/rest/job/submission/{submission_id}")
            for job in response:
                if job["job_status"] == VMRAY_JOB_STATUS_INWORK:
                    return True
            return False
        except Exception as err:
            logger.warning(f"Could not retrieve jobs for submission {submission_id}: {err}")
            return False

    def add_sample_results(self, sample: Sample, sample_summary = None):
        """Populate a sample with verdict, parsed IOCs, and VTIs from VMRay.

        Args:
            sample (Sample): Sample object to populate. Updated in place.
        """
        if sample_summary is None:
            sample_summary = self.get_sample_summary(sample.sample_sha256)
        if sample_summary is None:
            return
        if isinstance(sample_summary, list):
            if len(sample_summary) == 0:
                return
            sample_summary = sample_summary[0]
        sample_metadata = self.parse_sample_summary_data(sample_summary)
        sample.vmray_metadata = sample_metadata
        sample_ioc = self.get_sample_iocs(sample_metadata)
        sample.vmray_result = self.parse_sample_iocs(sample_ioc)

        sample_id = sample_metadata.get('sample_id')
        if sample_id:
            raw_vtis = self.get_sample_vtis(sample_id)
            sample.vmray_vtis = self.parse_sample_vtis(raw_vtis)

            threat_names = self.parse_sample_threat_names(self.get_sample_threat_names(sample_id))
            sample.vmray_result.setdefault('threat_names', set()).update(threat_names)

            classifications = self.parse_sample_classifications(self.get_sample_classifications(sample_id))
            sample.vmray_result.setdefault('classifications', set()).update(classifications)

        verdict_str = sample_metadata.get('sample_verdict', '')
        if verdict_str == VERDICT.MALICIOUS.value:
            sample.vmray_verdict = VERDICT.MALICIOUS
        elif verdict_str == VERDICT.SUSPICIOUS.value:
            sample.vmray_verdict = VERDICT.SUSPICIOUS
        else:
            sample.vmray_verdict = VERDICT.CLEAN

    def get_submission_analyses(self, submission_id):
        """Retrieve analysis records for a completed submission.

        Args:
            submission_id (int | str): VMRay submission ID.

        Returns:
            list | None: List of analysis dicts, or ``None`` if retrieval fails.
        """
        try:
            response = self.api.call("GET", f"/rest/analysis/submission/{submission_id}")
            return response
        except Exception as err:
            logger.warning(f"Could not retrieve analyses for submission {submission_id}: {err}")
            return None

    def check_submission_error(self, submission) -> bool:
        """Check whether any analysis in a submission has a non-zero result code.

        Args:
            submission (int | str): VMRay submission ID to inspect.

        Returns:
            bool: ``True`` if at least one analysis failed or if the analysis list
                could not be retrieved; ``False`` if all analyses completed cleanly.
        """
        analyses = self.get_submission_analyses(submission)
        if analyses is None:
            logger.warning(f"No analyses found for submission {submission}")
            return True
        for analysis in analyses:
            if analysis["analysis_verdict"] == "error":
                logger.error(f"Analysis {analysis['analysis_id']} (submission {submission}) failed: {analysis['analysis_result_str']}")
                return True
        return False
