"""CrowdStrike helper for the connector."""

import logging
from config.crowdstrike_conf import CrowdStrikeConfig
from config.general_conf import VERDICT
from config.constants import (
    CS_DATETIME_FORMAT,
    CS_PRODUCT_FILTER,
    CS_ALERTS_PAGE_LIMIT,
    CS_QUARANTINE_PAGE_LIMIT,
    CS_QUARANTINE_BATCH_SIZE,
    SAMPLE_ZIP_PASSWORD,
    HASH_READ_BUFFER_SIZE,
    IOC_TAGS,
    IOC_PLATFORMS,
    IOC_SEVERITY,
    IOC_ACTION_PREVENT,
    IOC_ACTION_DETECT,
    MAX_COMMENT_LENGTH,
)
from datetime import datetime, timedelta, timezone
from falconpy import Alerts, Quarantine, SampleUploads, IOC
import pathlib
import hashlib
import zipfile
from lib.Sample import Sample

logger = logging.getLogger(__name__)


class ConnectorDetect:
    """DTO for CrowdStrike EPP alert used by the connector.

    Attributes:
        composite_id (str): Unique composite alert identifier.
        timestamp (datetime): Time the alert was created.
        host_id (str): Device ID of the host that triggered the alert.
        included_sha256 (str): SHA-256 hash of the file that triggered the alert.
        os_version (str): Operating system version of the host.
        device_id (str): CrowdStrike agent device ID.
        file_path (str): File-system path of the flagged file on the host.
    """

    composite_id: str = ""
    timestamp: datetime = None
    host_id: str = ""
    included_sha256: str = ""
    os_version: str = ""
    device_id: str = ""
    file_path: str = ""

    def __init__(self, composite_id, timestamp, host_id, included_sha256, os_version, device_id, file_path) -> None:
        self.composite_id = composite_id
        self.timestamp = timestamp
        self.host_id = host_id
        self.included_sha256 = included_sha256
        self.os_version = os_version
        self.device_id = device_id
        self.file_path = file_path

    def __str__(self):
        return (
            f"composite_id={self.composite_id}, timestamp={self.timestamp}, "
            f"host_id={self.host_id}, sha256={self.included_sha256}, "
            f"os={self.os_version}, device_id={self.device_id}"
        )


class ConnectorQuarantine:
    """DTO for CrowdStrike quarantine item used by the connector.

    Attributes:
        quarantine_id (str): Unique quarantine identifier.
        quarantine_host_id (str): CrowdStrike agent ID (AID) of the host.
        timestamp (datetime): Time the quarantine record was created.
        sha256_hash (str): SHA-256 hash of the quarantined file.
        hostname (str): Hostname where the file was quarantined.
        filename (str): Original filename of the quarantined file.
    """

    quarantine_id: str = ""
    quarantine_host_id: str = ""
    timestamp: datetime = None
    sha256_hash: str = ""
    hostname: str = ""
    filename: str = ""

    def __init__(self, quarantine_id, timestamp, sha256_hash, hostname, filename, quarantine_host_id) -> None:
        self.quarantine_host_id = quarantine_host_id
        self.quarantine_id = quarantine_id
        self.timestamp = timestamp
        self.sha256_hash = sha256_hash
        self.hostname = hostname
        self.filename = filename

    def __str__(self):
        return (
            f"quarantine_id={self.quarantine_id}, timestamp={self.timestamp}, "
            f"filename={self.filename}, sha256={self.sha256_hash}, hostname={self.hostname}"
        )


class CrowdStrike:
    """Wrapper around the CrowdStrike FalconPy SDK used by the connector."""

    def __init__(self):
        self.alerts_api = None
        self.quarantine_api = None
        self.sample_api = None
        self.ioc_api = None
        self.config = CrowdStrikeConfig
        self._authenticate()

    def _authenticate(self):
        """Initialise and authenticate FalconPy API clients.

        Raises:
            Exception: If any of the API clients fails to authenticate.
        """
        logger.debug("Authenticating with CrowdStrike APIs")

        self.alerts_api = Alerts(
            client_id=self.config.CLIENT_ID,
            client_secret=self.config.CLIENT_SECRET,
            base_url=self.config.BASE_URL,
            ssl_verify=False
        )
        if self.alerts_api.authenticated():
            logger.info("CrowdStrike Alerts API authenticated")
        else:
            logger.error("CrowdStrike Alerts API authentication failed — check client ID/secret and permissions")
            raise Exception("CrowdStrike Alerts API authentication failed")

        self.quarantine_api = Quarantine(
            client_id=self.config.CLIENT_ID,
            client_secret=self.config.CLIENT_SECRET,
            base_url=self.config.BASE_URL,
            ssl_verify=False
        )
        if self.quarantine_api.authenticated():
            logger.info("CrowdStrike Quarantine API authenticated")
        else:
            logger.error("CrowdStrike Quarantine API authentication failed — check client ID/secret and permissions")
            raise Exception("CrowdStrike Quarantine API authentication failed")

        self.sample_api = SampleUploads(
            client_id=self.config.CLIENT_ID,
            client_secret=self.config.CLIENT_SECRET,
            base_url=self.config.BASE_URL,
            ssl_verify=False
        )
        if self.sample_api.authenticated():
            logger.info("CrowdStrike SampleUploads API authenticated")
        else:
            logger.error("CrowdStrike SampleUploads API authentication failed — check client ID/secret and permissions")
            raise Exception("CrowdStrike SampleUploads API authentication failed")

        self.ioc_api = IOC(
            client_id=self.config.CLIENT_ID,
            client_secret=self.config.CLIENT_SECRET,
            base_url=self.config.BASE_URL,
            ssl_verify=False
        )
        if self.ioc_api.authenticated():
            logger.info("CrowdStrike IOC API authenticated")
        else:
            logger.error("CrowdStrike IOC API authentication failed — check client ID/secret and permissions")
            raise Exception("CrowdStrike IOC API authentication failed")

        logger.info("All CrowdStrike API clients authenticated successfully")

    @staticmethod
    def _extract_error_msg(response: dict) -> str:
        """Extract a human-readable error message from a FalconPy response dict.

        Args:
            response (dict): Raw FalconPy response dictionary.

        Returns:
            str: The first error message found, or the full response as a string.
        """
        body = response.get('body', {}) if isinstance(response, dict) else {}
        errors = body.get('errors') or []
        if errors:
            return errors[0].get('message', str(errors[0]))
        message = body.get('message')
        if message:
            return message
        return str(response)

    def get_quarantines(self) -> list[ConnectorQuarantine]:
        """Retrieve quarantine files created within the configured time window.
        Paginates through all quarantine IDs using the query endpoint, then
        bulk-fetches quarantine details in batches of 100.

        Returns:
            list[ConnectorQuarantine]: Quarantine items found in the time window.

        Raises:
            Exception: If the CrowdStrike API returns an error at any pagination step.
        """
        quarantines_ids = []
        quarantines = []
        start_time = (datetime.now() - timedelta(seconds=self.config.TIME_SPAN)).strftime(CS_DATETIME_FORMAT)

        offset = 0
        limit = CS_QUARANTINE_PAGE_LIMIT
        while True:
            quarantines_response = self.quarantine_api.query_quarantine_files(
                filter=f"date_created:>'{start_time}'",
                limit=limit,
                offset=offset)
            if quarantines_response['body'].get('errors'):
                err_msg = self._extract_error_msg(quarantines_response)
                logger.error(f"Failed to query quarantine IDs: {err_msg}")
                raise Exception(f"Error occurred while getting quarantine ids. Error: {err_msg}")

            page_ids = quarantines_response['body'].get('resources') or []
            quarantines_ids.extend(page_ids)

            total = (quarantines_response['body'].get('meta') or {}).get('pagination', {}).get('total', 0)
            offset += len(page_ids)
            if not page_ids or offset >= total:
                break

        if len(quarantines_ids) == 0:
            logger.info(f"No quarantine files found in the last {self.config.TIME_SPAN}s")
            return []

        for i in range(0, len(quarantines_ids), CS_QUARANTINE_BATCH_SIZE):
            batch = quarantines_ids[i:i + CS_QUARANTINE_BATCH_SIZE]
            quarantines_response = self.quarantine_api.get_quarantine_files(ids=batch)
            if quarantines_response['body'].get('errors'):
                err_msg = self._extract_error_msg(quarantines_response)
                logger.error(f"Failed to retrieve quarantine file details: {err_msg}")
                raise Exception(f"Error occurred while getting quarantine information. Error: {err_msg}")

            for quarantine in (quarantines_response['body'].get('resources') or []):
                paths = quarantine.get('paths') or []
                filename = paths[0].get('filename', '') if paths else ''
                date_created = quarantine.get('date_created', '')
                try:
                    timestamp = datetime.strptime(date_created, CS_DATETIME_FORMAT)
                except (ValueError, TypeError):
                    logger.warning(f"Skipping quarantine {quarantine.get('id', '?')}: unparseable date '{date_created}'")
                    continue
                quarantines.append(ConnectorQuarantine(
                    quarantine_id=quarantine['id'],
                    timestamp=timestamp,
                    sha256_hash=quarantine['sha256'],
                    hostname=quarantine.get('hostname', ''),
                    filename=filename,
                    quarantine_host_id=quarantine.get('aid', '')))

        return quarantines

    def extract_hash_from_quarantines(self, quarantines: list[ConnectorQuarantine]) -> list[str]:
        """Extract SHA-256 hashes from a list of quarantine objects.

        Args:
            quarantines (list[ConnectorQuarantine]): Quarantine items to extract
                hashes from.

        Returns:
            list[str]: SHA-256 hashes of all quarantined files.
        """
        return [q.sha256_hash for q in quarantines]

    def get_alerts(self) -> list[ConnectorDetect]:
        """Retrieve EPP alerts created within the configured time window.

        Uses cursor-based pagination via the combined alerts endpoint to handle
        result sets larger than 1 000. Only alerts that include a SHA-256 hash
        are returned.

        Returns:
            list[ConnectorDetect]: Alert objects found in the time window.

        Raises:
            Exception: If the CrowdStrike API returns an error response.
        """
        alerts = []
        start_time = (datetime.now(timezone.utc) - timedelta(seconds=self.config.TIME_SPAN)).strftime(CS_DATETIME_FORMAT)
        fql_filter = f"created_timestamp:>'{start_time}'+product:'{CS_PRODUCT_FILTER}'"
        after = None

        while True:
            params = {"filter": fql_filter, "limit": CS_ALERTS_PAGE_LIMIT}
            if after:
                params["after"] = after

            response = self.alerts_api.get_alerts_combined(**params)

            if response['body'].get('errors'):
                err_msg = self._extract_error_msg(response)
                logger.error(f"Failed to retrieve alerts: {err_msg}")
                raise Exception(f"Error occurred while retrieving alerts: {err_msg}")

            resources = response['body'].get('resources') or []

            for alert in resources:
                sha256 = alert.get('sha256', '')
                composite_id = alert.get('composite_id', '')
                if not sha256 or not composite_id:
                    continue
                alerts.append(ConnectorDetect(
                    composite_id=composite_id,
                    timestamp=alert.get('created_timestamp', ''),
                    host_id=alert.get('device', {}).get('device_id', ''),
                    included_sha256=sha256,
                    file_path=alert.get('filepath', ''),
                    os_version=alert.get('device', {}).get('os_version', ''),
                    device_id=alert.get('device', {}).get('device_id', '')
                ))

            after = (response['body'].get('meta') or {}).get('pagination', {}).get('after')
            if not after or not resources:
                break

        if len(alerts) == 0:
            logger.info(f"No alerts found in the last {self.config.TIME_SPAN}s")

        return alerts

    def extract_hashes_from_alerts(self, detects: list[ConnectorDetect]) -> list[str]:
        """Extract SHA-256 hashes from a list of alert objects.

        Args:
            detects (list[ConnectorDetect]): Alert objects to extract hashes from.

        Returns:
            list[str]: SHA-256 hashes of all files included in the alerts.
        """
        return [d.included_sha256 for d in detects]

    def download_malware_sample(self, sample: Sample) -> None:
        """Download a sample from CrowdStrike SampleUploads, unzip, and verify integrity.

        Args:
            sample (Sample): Sample object
        """
        zipped_file_path = self.config.DOWNLOAD_DIR_PATH / pathlib.Path(sample.sample_sha256 + '.zip')
        unzipped_file_path = self.config.DOWNLOAD_DIR_PATH

        try:
            logger.debug(f"Downloading sample {sample.sample_sha256}")
            response = self.sample_api.get_sample(password_protected=True, ids=sample.sample_sha256)
            if isinstance(response, dict):
                error_msg = self._extract_error_msg(response)
                logger.warning(f"Download failed for {sample.sample_sha256}: {error_msg}")
                sample.downloaded_successfully = False
                return
        except Exception as err:
            logger.error(f"Download failed for {sample.sample_sha256}: {err}")
            sample.downloaded_successfully = False
            return

        try:
            with open(zipped_file_path, 'wb') as fh:
                fh.write(response)
            sample.zipped_path = str(zipped_file_path)
        except Exception as err:
            logger.error(f"Failed to write downloaded sample {sample.sample_sha256} to disk: {err}")
            sample.downloaded_successfully = False
            return

        try:
            with zipfile.ZipFile(zipped_file_path) as zip_file:
                zip_file.setpassword(SAMPLE_ZIP_PASSWORD.encode())
                zip_file.extract(sample.sample_sha256, unzipped_file_path)
            sample.unzipped_path = self.config.DOWNLOAD_DIR_PATH / pathlib.Path(sample.sample_sha256)
            if not self._check_file_integrity(sample=sample):
                logger.warning(f"Integrity check failed for sample {sample.sample_sha256}")
                sample.downloaded_successfully = False
                return
        except Exception as err:
            logger.error(f"Failed to extract or verify sample {sample.sample_sha256}: {err}")
            sample.downloaded_successfully = False
            return

        logger.info(f"Sample {sample.sample_sha256} downloaded and verified successfully")
        sample.downloaded_successfully = True

    def _check_file_integrity(self, sample: Sample) -> bool:
        """Verify the SHA-256 of the extracted file matches the sample's expected hash.

        Args:
            sample (Sample): Sample object

        Returns:
            bool: ``True`` if the computed digest matches, ``False`` otherwise.
        """
        calculated = hashlib.sha256()
        with open(sample.unzipped_path, "rb") as file:
            for byte_block in iter(lambda: file.read(HASH_READ_BUFFER_SIZE), b""):
                calculated.update(byte_block)
        return calculated.hexdigest() == sample.sample_sha256

    def check_ioc(self, ioc_type: str, value: str) -> bool:
        """Check whether an IOC already exists in CrowdStrike.

        Args:
            ioc_type (str): IOC type, e.g. ``"sha256"``, ``"ipv4"``, or ``"domain"``.
            value (str): IOC value to look up.

        Returns:
            bool: ``True`` if the IOC exists, ``False`` if it does not or if the
                lookup fails.
        """
        try:
            safe_value = str(value).replace("\\", "\\\\").replace("'", "\\'")
            response = self.ioc_api.indicator_search(filter=f"type:'{ioc_type}'+value:'{safe_value}'")
            if response['body'].get('errors'):
                logger.error(f"IOC lookup failed ({ioc_type}:{value}): {self._extract_error_msg(response)}")
                return False
            return bool(response["body"].get("resources"))
        except Exception as err:
            logger.error(f"IOC lookup failed ({ioc_type}:{value}): {err}")
            return False

    def create_ioc(self, sample: Sample) -> None:
        """Create CrowdStrike IOCs from the VMRay analysis results for a sample.

        Args:
            sample (Sample): Sample object
        """
        try:
            if not self.check_ioc(ioc_type="sha256", value=sample.sample_sha256):
                response = self.ioc_api.indicator_create(
                    action=IOC_ACTION_PREVENT, type='sha256', value=sample.sample_sha256,
                    applied_globally=True, severity=IOC_SEVERITY,
                    platforms=IOC_PLATFORMS, tags=IOC_TAGS,
                    description=f'IOC for {sample.sample_sha256} found by VMRAY')
                if response['body'].get('errors'):
                    logger.error(f"Failed to create sha256 IOC {sample.sample_sha256}: {self._extract_error_msg(response)}")
                else:
                    logger.info(f"Created sha256 IOC: {sample.sample_sha256}")

            for ip in sample.vmray_result.get('ipv4', set()):
                if not self.check_ioc(ioc_type="ipv4", value=ip):
                    response = self.ioc_api.indicator_create(
                        action=IOC_ACTION_DETECT, type='ipv4', value=ip,
                        applied_globally=True, platforms=IOC_PLATFORMS,
                        severity=IOC_SEVERITY, tags=IOC_TAGS,
                        description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if response['body'].get('errors'):
                        logger.error(f"Failed to create ipv4 IOC {ip}: {self._extract_error_msg(response)}")
                    else:
                        logger.info(f"Created ipv4 IOC: {ip}")

            for found_sha256 in sample.vmray_result.get('sha256', set()):
                if not self.check_ioc(ioc_type="sha256", value=found_sha256):
                    response = self.ioc_api.indicator_create(
                        action=IOC_ACTION_PREVENT, type='sha256', value=found_sha256,
                        applied_globally=True, severity=IOC_SEVERITY,
                        platforms=IOC_PLATFORMS, tags=IOC_TAGS,
                        description=f'IOC for {found_sha256} found by VMRAY')
                    if response['body'].get('errors'):
                        logger.error(f"Failed to create sha256 IOC {found_sha256}: {self._extract_error_msg(response)}")
                    else:
                        logger.info(f"Created sha256 IOC: {found_sha256}")

            for domain in sample.vmray_result.get('domain', set()):
                if not self.check_ioc(ioc_type="domain", value=domain):
                    response = self.ioc_api.indicator_create(
                        action=IOC_ACTION_DETECT, type='domain', value=domain,
                        applied_globally=True, platforms=IOC_PLATFORMS,
                        severity=IOC_SEVERITY, tags=IOC_TAGS,
                        description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if response['body'].get('errors'):
                        logger.error(f"Failed to create domain IOC {domain}: {self._extract_error_msg(response)}")
                    else:
                        logger.info(f"Created domain IOC: {domain}")

        except Exception as err:
            logger.error(f"Unexpected error creating IOCs for {sample.sample_sha256}: {err}")

    def update_quarantine(self, quarantine_id: str, comment: str, action: str) -> None:
        """Update a CrowdStrike quarantine item with a comment and disposition action.

        Args:
            quarantine_id (str): Quarantine record ID to update.
            comment (str): Comment text to attach to the quarantine record.
            action (str): Disposition action — either ``"release"`` or
                ``"unrelease"``.
        """
        try:
            response = self.quarantine_api.update_quarantined_detects_by_id(
                ids=quarantine_id, comment=comment, action=action)
            if response["status_code"] != 200 or response['body'].get('errors'):
                logger.error(f"Failed to update quarantine {quarantine_id}: {self._extract_error_msg(response)}")
        except Exception as err:
            logger.error(f"Failed to update quarantine {quarantine_id}: {err}")

    def update_alert(self, composite_id: str, comment: str) -> None:
        """Append a comment to a CrowdStrike alert.

        Args:
            composite_id (str): Composite alert ID to update.
            comment (str): Comment text to append to the alert.
        """
        try:
            response = self.alerts_api.update_alerts_v3(
                composite_ids=[composite_id],
                append_comment=comment)
            if response["status_code"] != 200 or response['body'].get('errors'):
                logger.error(f"Failed to update alert {composite_id}: {self._extract_error_msg(response)}")
        except Exception as err:
            logger.error(f"Failed to update alert {composite_id}: {err}")

    @staticmethod
    def _split_inline_section(header: str, cont_header: str, items: list[str], max_len: int) -> list[str]:
        """Split 'header: item1, item2, ...' into chunks each ≤ max_len."""
        if not items:
            return []
        chunks = []
        current_header = header
        current_batch = []
        for item in items:
            candidate = current_header + ", ".join(current_batch + [item])
            if len(candidate) <= max_len:
                current_batch.append(item)
            else:
                if current_batch:
                    chunks.append(current_header + ", ".join(current_batch))
                    current_header = cont_header
                    current_batch = [item]
                else:
                    chunks.append(current_header + item)
                    current_header = cont_header
        if current_batch:
            chunks.append(current_header + ", ".join(current_batch))
        return chunks

    @staticmethod
    def _split_block_section(header: str, cont_header: str, lines: list[str], max_len: int) -> list[str]:
        """Split 'header\\nline1\\nline2\\n...' into chunks each ≤ max_len."""
        if not lines:
            return []
        chunks = []
        current_header = header
        current_lines = []
        for line in lines:
            candidate = current_header + "\n".join(current_lines + [line])
            if len(candidate) <= max_len:
                current_lines.append(line)
            else:
                if current_lines:
                    chunks.append(current_header + "\n".join(current_lines))
                    current_header = cont_header
                    current_lines = [line]
                else:
                    chunks.append(current_header + line)
                    current_header = cont_header
        if current_lines:
            chunks.append(current_header + "\n".join(current_lines))
        return chunks

    @staticmethod
    def build_detection_comments(sample) -> list[str]:
        """Build one or more structured comments for a CrowdStrike detection.

        Args:
            sample (Sample): Fully populated sample object

        Returns:
            list[str]: Ordered list of comment strings ready to post to CrowdStrike.
                Always contains at least one element.
        """
        if sample.vmray_verdict == VERDICT.CLEAN:
            return ["[VMRay] Verdict: Clean — no threats detected."]

        verdict = sample.vmray_verdict.value.capitalize()
        webif_url = sample.vmray_metadata.get('sample_webif_url', '')
        classifications = sorted(sample.vmray_result.get('classifications', set()))
        threat_names = sorted(sample.vmray_result.get('threat_names', set()))
        vtis = sample.vmray_vtis or []

        # Section 1: Verdict + Analysis URL
        verdict_line = f"[VMRay] Verdict: {verdict}"
        if webif_url:
            verdict_line += f" | Analysis: {webif_url}"
        chunks_verdict = [verdict_line]

        # Section 2: Threat names (comma-separated, split if needed)
        chunks_threat = CrowdStrike._split_inline_section(
            "Threat Names: ", "Threat Names (cont.): ", threat_names, MAX_COMMENT_LENGTH
        )

        # Section 3: Classifications (comma-separated, split if needed)
        chunks_class = CrowdStrike._split_inline_section(
            "Classifications: ", "Classifications (cont.): ", classifications, MAX_COMMENT_LENGTH
        )

        # Section 4: VTIs, one line per entry, sorted by score descending
        sorted_vtis = sorted(vtis, key=lambda vti: vti.get('score') or 0, reverse=True)
        vti_lines = []
        for vti in sorted_vtis:
            cat = vti.get('category', 'Unknown')
            operation = vti.get('operation', '')
            score = vti.get('score', '')
            line = f"{score} | {cat} | {operation}" if score else f"{cat} | {operation}"
            vti_lines.append(line)
        chunks_vtis = CrowdStrike._split_block_section(
            "VTIs (Score | Category | Operation):\n",
            "VTIs (Score | Category | Operation) (cont.):\n",
            vti_lines,
            MAX_COMMENT_LENGTH
        )

        # Combine all section chunks into comments ≤ MAX_COMMENT_LENGTH
        all_chunks = chunks_verdict + chunks_threat + chunks_class + chunks_vtis

        comments = []
        current = ""
        for chunk in all_chunks:
            if not current:
                current = chunk
            elif len(current) + 1 + len(chunk) <= MAX_COMMENT_LENGTH:
                current += "\n" + chunk
            else:
                comments.append(current)
                current = chunk
        if current:
            comments.append(current)

        return comments