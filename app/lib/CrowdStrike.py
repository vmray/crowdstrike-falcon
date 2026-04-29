from config.crowdstrike_conf import CrowdStrikeConfig
from datetime import datetime, timedelta
from falconpy import Alerts, Quarantine, SampleUploads, IOC
import pathlib
import hashlib
import zipfile
from lib.Sample import Sample


class ConnectorDetect:
    """
      Alert Class to keep alerts as an object in connector.
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
        return f" Composite ID : {self.composite_id}, Created Time : {self.timestamp}, Host ID: {self.host_id}, sha256: {self.included_sha256}, host OS: {self.os_version}, device id: {self.device_id}"


class ConnectorQuarantine:
    """
      Quarantine Class to keep quarantines as an object in connector
    """
    quarantine_id: str = ""
    quarantine_host_id: str = ""
    timestamp: datetime = None
    sha256_hash: str = ""
    hostname: str = ""
    filename: str = ""
    vmray_result: str = ""

    def __init__(self, quarantine_id, timestamp, sha256_hash, hostname, filename, quarantine_host_id) -> None:
        self.quarantine_host_id = quarantine_host_id
        self.quarantine_id = quarantine_id
        self.timestamp = timestamp
        self.sha256_hash = sha256_hash
        self.hostname = hostname
        self.filename = filename

    def __str__(self):
        return f" Quarantine ID : {self.quarantine_id}, Created Time : {self.timestamp}, Filename: {self.filename}, sha256: {self.sha256_hash}, Hostname: {self.hostname} "


class CrowdStrike:
    """
      Wrapper Class for CrowdStrike's functions.
    """

    def __init__(self, log):
        self.alerts_api = None
        self.quarantine_api = None
        self.sample_api = None
        self.ioc_api = None
        self.log = log
        self.config = CrowdStrikeConfig
        self._authenticate()

    def _authenticate(self):
        """
          authenticate with Alerts, Quarantine and Host services
        """
        self.log.debug("authentication has been started!")
        self.alerts_api = Alerts(
            client_id=self.config.CLIENT_ID,
            client_secret=self.config.CLIENT_SECRET,
            base_url=self.config.BASE_URL)
        if self.alerts_api.authenticated():
            self.log.debug("CrowdStrike Alerts API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Alerts API could not connect! Check secrets and permissions!")
            raise Exception("CrowdStrike Alerts API could not connect! Check secrets and permissions!")

        self.quarantine_api = Quarantine(
            client_id=self.config.CLIENT_ID, 
            client_secret=self.config.CLIENT_SECRET, 
            base_url=self.config.BASE_URL)
        if self.quarantine_api.authenticated():
            self.log.debug("CrowdStrike Quarantine API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Quarantine API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike Quarantine API could not connect. Check secrets and permissions!")

        self.sample_api = SampleUploads(client_id=self.config.CLIENT_ID, 
                                        client_secret=self.config.CLIENT_SECRET, 
                                        base_url=self.config.BASE_URL)
        if self.sample_api.authenticated():
            self.log.debug(
                "CrowdStrike SampleUpload API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike SampleUpload API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike SampleUpload API could not connect. Check secrets and permissions!")
        
        self.ioc_api = IOC(client_id=self.config.CLIENT_ID, 
                           client_secret=self.config.CLIENT_SECRET,
                           base_url=self.config.BASE_URL)
        if self.ioc_api.authenticated():
            self.log.info(
                "CrowdStrike IOC API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike IOC API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike IOC API could not connect. Check secrets and permissions!")

    @staticmethod
    def _extract_error_msg(response: dict) -> str:
        """Safely extract a human-readable error message from a FalconPy response dict."""
        body = response.get('body', {}) if isinstance(response, dict) else {}
        errors = body.get('errors') or []
        if errors:
            return errors[0].get('message', str(errors[0]))
        message = body.get('message')
        if message:
            return message
        return str(response)

    def get_quarantines(self) -> list[ConnectorQuarantine]:
        """
          Gets quarantines object from CrowdStrike and create ConnectorQuarantine object for future usage.

        Raises:
            Exception: CrowdStrike Cloud SDK exceptions while getting quarantine ids
            Exception: CrowdStrike Cloud SDK exceptions while getting quarantines object within given time span

        Returns:
            list[ConnectorQuarantine]: List of ConnectorQuarantine objects
        """
        quarantines_ids = []
        quarantines = []
        start_time = (datetime.now(
        ) - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Paginate through all quarantine IDs
        offset = 0
        limit = 5000
        while True:
            quarantines_response = self.quarantine_api.query_quarantine_files(
                filter=f"date_created:>'{start_time}'",
                limit=limit,
                offset=offset)
            if quarantines_response['body'].get('errors'):
                err_msg = self._extract_error_msg(quarantines_response)
                self.log.error(f"Error while getting quarantine ids information: {err_msg}")
                raise Exception(f"Error occurred while getting quarantine ids. Error: {err_msg}")

            page_ids = quarantines_response['body'].get('resources') or []
            quarantines_ids.extend(page_ids)

            total = (quarantines_response['body'].get('meta') or {}).get('pagination', {}).get('total', 0)
            offset += len(page_ids)
            if not page_ids or offset >= total:
                break

        if len(quarantines_ids) == 0:
            self.log.info(
                f"No quarantine files in the last {self.config.TIME_SPAN} seconds!")
            return []

        # Bulk-fetch quarantine details in batches of 100 (CrowdStrike /entities/ limit)
        batch_size = 100
        for i in range(0, len(quarantines_ids), batch_size):
            batch = quarantines_ids[i:i + batch_size]
            quarantines_response = self.quarantine_api.get_quarantine_files(ids=batch)
            if quarantines_response['body'].get('errors'):
                err_msg = self._extract_error_msg(quarantines_response)
                self.log.error(f"Error while getting quarantine file information: {err_msg}")
                raise Exception(f"Error occurred while getting quarantine information. Error: {err_msg}")

            for quarantine in (quarantines_response['body'].get('resources') or []):
                paths = quarantine.get('paths') or []
                filename = paths[0]['filename'] if paths else ''
                quarantines.append(ConnectorQuarantine(quarantine_id=quarantine['id'],
                                                       timestamp=datetime.strptime(
                                                           quarantine['date_created'], '%Y-%m-%dT%H:%M:%SZ'),
                                                       sha256_hash=quarantine['sha256'],
                                                       hostname=quarantine['hostname'],
                                                       filename=filename,
                                                       quarantine_host_id=quarantine['aid']))

        return quarantines

    def extract_hash_from_quarantines(self, quarantines: list[ConnectorQuarantine]) -> list[str]:
        """extract hashes from quarantines

        Args:
            quarantines (list[ConnectorQuarantine]): list of quarantines

        Returns:
            list[str]: hashes of quarantine files
        """
        hash_list = []
        for quarantine in quarantines:
            hash_list.append(quarantine.sha256_hash)
        return hash_list

    def get_alerts(self) -> list[ConnectorDetect]:
        """Retrieve alerts from CrowdStrike using the combined alerts endpoint (POST /alerts/combined/alerts/v1).
        Uses cursor-based pagination to handle result sets larger than 1000.

        Raises:
            Exception: API error while retrieving alerts
        Returns:
            list[ConnectorDetect]: list of ConnectorDetect objects populated from alert data
        """
        alerts = []
        start_time = (datetime.now(
        ) - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        fql_filter = f"created_timestamp:>'{start_time}'+product:'epp'"
        after = None

        while True:
            params = {"filter": fql_filter, "limit": 1000}
            if after:
                params["after"] = after

            response = self.alerts_api.get_alerts_combined(**params)

            if response['body'].get('errors'):
                err_msg = self._extract_error_msg(response)
                self.log.error(f"Error while retrieving alerts: {err_msg}")
                raise Exception(f"Error occurred while retrieving alerts: {err_msg}")

            resources = response['body'].get('resources') or []

            for alert in resources:
                sha256 = alert.get('sha256', '')
                if not sha256:
                    continue
                alerts.append(ConnectorDetect(
                    composite_id=alert['composite_id'],
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
            self.log.info(f"No alerts in the last {self.config.TIME_SPAN} seconds!")

        return alerts

    def extract_hashes_from_alerts(self, detects: list[ConnectorDetect]) -> list[str]:
        """extract hashes from alerts

        Args:
            detects (list[ConnectorDetect]): list of ConnectorDetect objects populated from CrowdStrike Alerts API

        Returns:
            list[str]: hash list of included files in detects
        """
        hash_list = []
        for detect in detects:
            hash_list.append(detect.included_sha256)
        return hash_list

    def download_malware_sample(self, sample: Sample) -> None:
        """
          Download files from CrowdStrike found on Alerts and Quarantines services and update relevant sample object
        Args:
            sample: Sample Object
        """
        self.log.debug(f"Samples' downloading process has been started!")

        zipped_file_path = self.config.DOWNLOAD_DIR_PATH / \
            pathlib.Path(sample.sample_sha256 + '.zip')
        unzipped_file_path = self.config.DOWNLOAD_DIR_PATH
        try:
            self.log.debug(f"Downloading sample {sample.sample_sha256}")
            response = self.sample_api.get_sample(
                password_protected=True, ids=sample.sample_sha256)
            if isinstance(response, dict):
                errors = response['body'].get('errors')
                if errors:
                    error_msg = self._extract_error_msg(response)
                self.log.error(
                    f"File cannot be downloaded! Error: {error_msg}")
                sample.downloaded_successfully = False
                return
        except Exception as err:
            self.log.error(
                f"file with {sample.sample_sha256} hash cannot be downloaded. Error: {err}")
            sample.downloaded_successfully = False
            return
        try:
            with open(zipped_file_path, 'wb') as fh:
                fh.write(response)
            sample.zipped_path = str(zipped_file_path)
        except Exception as err:
            self.log.error(
                f"file with {sample.sample_sha256} hash cannot be written into a file. Error: {err}")
            sample.downloaded_successfully = False
            return
        try:
            # Extract zip file
            with zipfile.ZipFile(zipped_file_path) as zip_file:
                # Set the password for the ZIP file
                zip_file.setpassword('infected'.encode())
                zip_file.extract(sample.sample_sha256, unzipped_file_path)
            # set Sample object's file path
            sample.unzipped_path = self.config.DOWNLOAD_DIR_PATH / pathlib.Path(sample.sample_sha256)
            if not self._check_file_integrity(sample=sample):
                sample.downloaded_successfully = False
                return
        except Exception as err:
            self.log.error(
                f"cannot check integrity {sample.sample_sha256} hashed file Error: {err}")
            sample.downloaded_successfully = False
            return
        sample.downloaded_successfully = True

    def _check_file_integrity(self, sample: Sample) -> bool:
        """
          Check integrity of the downloaded files
        Args:
            sample (Sample): sample object
        Returns:
            bool: if integrity is ok return True else False
        """
        calculated_sha256_hash = hashlib.sha256()
        with open(sample.unzipped_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                calculated_sha256_hash.update(byte_block)
        if calculated_sha256_hash.hexdigest() == sample.sample_sha256:
            return True

        return False
    
    def check_ioc(self, type: str, value: str) -> bool:
        """Check ioc exist or not
        
        Args:
            type (str): type of IOC (domain, ip, sha256)
            value (str): value of IOC
        
        Returns: True if ioc exist else False
        """
        try:
            response = self.ioc_api.indicator_search(filter=f"type:'{type}'+value:'{value}'")
            if response['body'].get('errors'):
                self.log.error(f"API error checking IOC {type}:{value}: {self._extract_error_msg(response)}")
                return False
            if not response["body"].get("resources"):
                return False
        except Exception as err:
            self.log.error(f"Cannot check ioc {type}:{value}: {err}")
            return False
        return True
    
    def create_ioc(self, sample: Sample) -> None:
        """Create iocs with detect policy for given sample's sha256 and vmray result
        Args:
            type (str): type of IOC (domain, ip, sha256)
            value (str): value of IOC
        """
        try:
            # create ioc with sample sha256
            if not self.check_ioc(type="sha256", value=sample.sample_sha256):
                response = self.ioc_api.indicator_create(action='prevent',
                                                         type='sha256', 
                                                         value=sample.sample_sha256, 
                                                         applied_globally=True,
                                                         severity='high',
                                                         platforms=['mac','windows','linux'],
                                                         tags=['VMRAY'],
                                                         description=f'IOC for {sample.sample_sha256} found by VMRAY')
                if response['body'].get('errors'):
                    self.log.error(f"Cannot create ioc {sample.sample_sha256}: {self._extract_error_msg(response)}")

            # create iocs with ipv4 found in vmray result
            for ip in sample.vmray_result.get('ipv4', set()):
                if not self.check_ioc(type="ipv4", value=ip):
                    response = self.ioc_api.indicator_create(action='detect',
                                                             type='ipv4',
                                                             value=ip,
                                                             applied_globally=True,
                                                             platforms=['mac','windows','linux'],
                                                             severity='high',
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if response['body'].get('errors'):
                        self.log.error(f"Cannot create ioc {ip}: {self._extract_error_msg(response)}")

            # create iocs with sha256 found in vmray result
            for found_sha256 in sample.vmray_result.get('sha256', set()):
                if not self.check_ioc(type="sha256", value=found_sha256):
                    response = self.ioc_api.indicator_create(action='prevent',
                                                             type='sha256',
                                                             value=found_sha256,
                                                             applied_globally=True,
                                                             severity='high',
                                                             platforms=['mac','windows','linux'],
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {found_sha256} found by VMRAY')
                    if response['body'].get('errors'):
                        self.log.error(f"Cannot create ioc {found_sha256}: {self._extract_error_msg(response)}")

            # create iocs with domain found in vmray result
            for domain in sample.vmray_result.get('domain', set()):
                if not self.check_ioc(type="domain", value=domain):
                    response = self.ioc_api.indicator_create(action='detect',
                                                             type='domain',
                                                             value=domain,
                                                             applied_globally=True,
                                                             platforms=['mac','windows','linux'],
                                                             severity='high',
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if response['body'].get('errors'):
                        self.log.error(f"Cannot create ioc {domain}: {self._extract_error_msg(response)}")
        except Exception as err:
            self.log.error(f"Cannot create ioc {sample.sample_sha256} because of {err}")
         
    
    def update_quarantine(self, quarantine_id: str, comment: str, action: str) -> None:
        """Update quarantine with given id

        Args:
            quarantine_id (str): quarantine id in crowdstrike
            comment (str): comment to add to quarantine object
            action (str): action to take on quarantine object
        """
        try:
            response = self.quarantine_api.update_quarantined_detects_by_id(ids=quarantine_id, comment=comment, action=action)
            if response["status_code"] != 200 or response['body'].get('errors'):
                self.log.error(f"Cannot update quarantine {quarantine_id}: {self._extract_error_msg(response)}")    

        except Exception as err:
            self.log.error(f"Cannot update quarantine {quarantine_id}: {err}")

    
    def update_alert(self, composite_id: str, comment: str) -> None:
        """Append a comment to an alert via PATCH /alerts/entities/alerts/v3.

        Args:
            composite_id (str): composite alert ID
            comment (str): comment to append to the alert
        """
        try:
            response = self.alerts_api.update_alerts_v3(
                composite_ids=[composite_id],
                append_comment=comment
            )
            if response["status_code"] != 200 or response['body'].get('errors'):
                self.log.error(f"Cannot update alert {composite_id}: {self._extract_error_msg(response)}")
        except Exception as err:
            self.log.error(f"Cannot update alert {composite_id}: {err}")

