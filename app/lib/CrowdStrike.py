from typing import Any
from config.crowdstrike_conf import CrowdStrikeConfig
from datetime import datetime, timedelta
from falconpy import Detects, Quarantine, Hosts, SampleUploads, ODS, IOC, MessageCenter
import pathlib
import hashlib
import zipfile
from lib.Sample import Sample


class ConnectorDetect:
    """
      Detect Class to keep detects as an object in connector.
    """
    detect_id: str = ""
    timestamp: datetime = None
    host_id: str = ""
    included_sha256: str = ""
    os_version: str = ""
    device_id: str = ""
    file_path: str = ""

    def __init__(self, detect_id, timestamp, host_id, included_sha256, os_version, device_id, file_path) -> None:
        self.detect_id = detect_id
        self.timestamp = timestamp
        self.host_id = host_id
        self.included_sha256 = included_sha256
        self.os_version = os_version
        self.device_id = device_id
        self.file_path = file_path

    def __str__(self):
        return f" Detect ID : {self.detect_id}, Created Time : {self.timestamp}, Host ID: {self.host_id}, sha256: {self.included_sha256}, host OS: {self.os_version}, device id: {self.device_id}"


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
        self.detect_api = None
        self.quarantine_api = None
        self.host_api = None
        self.sample_api = None
        self.ods_api = None
        self.ioc_api = None
        self.message_center_api = None
        self.log = log
        self.config = CrowdStrikeConfig
        self._authanticate()

    def _authanticate(self):
        """
          authanticate with Detect, Quarantine and Host services
        """
        self.log.debug("authantication has been started!")
        self.detect_api = Detects(
            client_id=self.config.CLIENT_ID, client_secret=self.config.CLIENT_SECRET)
        if self.detect_api.authenticated() is not None:
            self.log.info("CrowdStrike Detection API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Detection API could not connect! Check secrets and permissions!")
            raise Exception

        self.quarantine_api = Quarantine(
            client_id=self.config.CLIENT_ID, client_secret=self.config.CLIENT_SECRET)
        if self.quarantine_api is not None:
            self.log.info("CrowdStrike Detection API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Detection API could not connect. Check secrets and permissions!")
            raise Exception

        self.host_api = Hosts(client_id=self.config.CLIENT_ID,
                              client_secret=self.config.CLIENT_SECRET)
        if self.host_api is not None:
            self.log.info("CrowdStrike Host API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Host API could not connect. Check secrets and permissions!")
            raise Exception
        self.sample_api = SampleUploads(client_id=self.config.CLIENT_ID, client_secret=self.config.CLIENT_SECRET)
        if self.sample_api is not None:
            self.log.info(
                "CrowdStrike SampleUpload API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike SampleUpload API could not connect. Check secrets and permissions!")
            raise Exception
        self.ods_api = ODS(client_id=self.config.CLIENT_ID, client_secret=self.config.CLIENT_SECRET)
        if self.ods_api is not None:
            self.log.info(
                "CrowdStrike ODS API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike ODS API could not connect. Check secrets and permissions!")
            raise Exception
        self.ioc_api = IOC(client_id=self.config.CLIENT_ID, client_secret=self.config.CLIENT_SECRET)
        if self.ioc_api is not None:
            self.log.info(
                "CrowdStrike IOC API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike IOC API could not connect. Check secrets and permissions!")
            raise Exception
        self.message_center_api = MessageCenter(client_id=self.config.CLIENT_ID, client_secret=self.config.CLIENT_SECRET)
        if self.message_center_api is not None:
            self.log.info(
                "CrowdStrike Message Center API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Message Center API could not connect. Check secrets and permissions!")
            raise Exception

    def get_quarantines(self) -> list[ConnectorQuarantine]:
        """
          Gets quarantines object from CrowdStrike and create ConnectorQuarantine object for furture usage.

        Raises:
            Exception: CrowdStrike Cloud SDK exceptions while getting quarantines ids
            Exception: CrowdStike Cloud SDK exceptions while getting quarantines object with in given time span

        Returns:
            list[ConnectorQuarantine]: List of ConnectorQuarantine objects
        """
        quarantines_ids = []
        quarantines = []
        start_time = (datetime.now(
        ) - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        quarantines_response = self.quarantine_api.query_quarantine_files(
            filter=f"date_created:>'{start_time}'")
        if len(quarantines_response['body']['errors']) > 0:
            self.log.error(
                f"Error while getting quarantine ids information: Error : {quarantines_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occured while getting quarantine ids. Error : {quarantines_response['errors'][0]['message']}")

        quarantines_ids = quarantines_response['body']['resources']
        if len(quarantines_ids) == 0:
            self.log.info(
                f"There is no quarantine files since {self.config.TIME_SPAN} seconds!")
            return []
        quarantines_response = self.quarantine_api.get_quarantine_files(
            ids=quarantines_ids)
        if len(quarantines_response['body']['errors']) > 0:
            self.log.error(
                f"Error while getting quarantine file information: Error : {quarantines_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occured while getting quarantine informations. Error : {quarantines_response['errors'][0]['message']}")

        for quarantine in quarantines_response['body']['resources']:
            quarantines.append(ConnectorQuarantine(quarantine_id=quarantine['id'],
                                                   timestamp=datetime.strptime(
                                                       quarantine['date_created'], '%Y-%m-%dT%H:%M:%SZ'),
                                                   sha256_hash=quarantine['sha256'],
                                                   hostname=quarantine['hostname'],
                                                   filename=quarantine['paths'][0]['filename'],
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

    def get_detects(self) -> list[ConnectorDetect]:
        """_summary_

        Raises:
            Exception: Query API Error while getting detect ids
            Exception: API Error while getting detect objects
        Returns:
            list[ConnectorDetect]: list OF ConnectorDetect objects
        """
        detects_ids = []
        detects = []
        start_time = (datetime.now(
        ) - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        detect_response = self.detect_api.query_detects(
            filter=f"created_timestamp:>'{start_time}'")
        if len(detect_response['body']['errors']) > 0:
            self.log.error(
                f"Error while getting detect ids information: Error : {detect_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occured while getting detect ids. Error : {detect_response['errors'][0]['message']}")

        detects_ids = detect_response['body']["resources"]
        if len(detects_ids) == 0:
            self.log.info(
                f"There is no detect files since {self.config.TIME_SPAN} seconds!")
            return []
        detect_response = self.detect_api.get_detect_summaries(ids=detects_ids)
        if len(detect_response['body']['errors']) > 0:
            self.log.error(
                f"Error while getting detect file information: Error : {detect_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occured while getting detect informations. Error : {detect_response['errors'][0]['message']}")

        for detect in detect_response['body']['resources']:
            detects.append(ConnectorDetect(detect_id=detect['detection_id'],
                                            timestamp=detect['created_timestamp'],
                                            host_id=detect['device']['device_id'],
                                            included_sha256=detect['behaviors'][0]['sha256'],
                                            file_path=detect['behaviors'][0]['filepath'],
                                            os_version=detect['device']['os_version'],
                                            device_id=detect['device']['device_id']))
        return detects

    def extract_hashes_from_detects(self, detects: list[ConnectorDetect]) -> list[str]:
        """extract hashes from detects

        Args:
            detects (list[ConnectorDetect]): list of ConnectorDetect objects with filled with CriwdStrike Detect API

        Returns:
            list[str]: hash list of included files in detects
        """
        hash_list = []
        for detect in detects:
            hash_list.append(detect.included_sha256)
        return hash_list

    def find_detect_id_from_quarantine(self, quarantine_id: str) -> list[str]:
        """if there is a detect id in quarantine, this function returns it.

        Args:
            quarantine_id (str): quaranitne id

        Raises:
            Exception: no quarantine with given id
            Exception: no detect id in quarantine

        Returns:
            list[str]: list of detect ids
        """
        quarantine_response = self.quarantine_api.GetQuarantineFiles(
            ids=quarantine_id)
        if len(quarantine_response["body"]["errors"]) > 0:
            self.log.error(
                f"Error while getting detect ids information: Error : {quarantine_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occured while getting detect ids. Error : {quarantine_response['errors'][0]['message']}")
        if len(quarantine_response["body"]["resources"]) == 0:
            self.log.info(f"There is no quarantine with given quarantine id!")
            raise Exception(
                message=f"There is no quarantine with given quarantine id!")
        if len(quarantine_response["body"]["resources"]["detect_ids"]) == 0:
            self.log.info(
                f"There is no detect object with given quarantine id!")
            return []
        return quarantine_response["body"]["resources"]["detects_ids"]

    def download_malware_sample(self, sample: Sample) -> None:
        """
          Download files from CrowdStrike found on Detectins and Quarantines services and update relevant sample object
        Args:
            sample: Sample Object
        """
        self.log.debug(f"Samples' downloading process has been started!")

        zipped_file_path = self.config.DOWNLOAD_DIR_PATH / \
            pathlib.Path(sample.sample_sha256 + '.zip')
        unzipped_file_path = self.config.DOWNLOAD_DIR_PATH
        try:
            response = self.sample_api.get_sample(
                password_protected=True, ids=sample.sample_sha256)
            if type(response) == dict:
                self.log.error(
                    f"File cannot be downloaded! Error : {response['errors'][0]['message']}")
                sample.downloaded_successfully = False
                return
        except Exception as err:
            self.log.error(
                f"file with {sample.sample_sha256} hash cannot be downloaded. Error: {err}")
            sample.downloaded_successfully = False
            return
        try:
            open(zipped_file_path, 'wb').write(response)
            sample.zipped_path = zipped_file_path
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
        with open(sample.zipped_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                calculated_sha256_hash.update(byte_block)
            if calculated_sha256_hash == sample.sample_sha256:
                return True

        return False
    
    def start_on_demand_scan(self, host_os: str, host_id: str, filepath:str) -> None:
        """Start on demand scan on given host if host os is windows

        Args:
            host_id (str): host id for scan
            filepath (str): malicious file path
        """
        try:
            if 'windows' in host_os.lower():
                response = self.ods_api.create_scan(host_id=host_id, file_paths=filepath, cpu_priority=1)
            if len(response["body"]["errors"]) > 0:
                self.log.error(f"Host {host_id} cannot start on demand scan Error : {response['errors'][0]['message']}")
                return    
            self.log.info(f"On Demand Scan has been started on host {host_id}")
        except:
            self.log.error(f"Cannot start on demand scan on host {host_id}")
        return
    
    def contain_host(self, host_id: str):
        """contain host

        Args:
            host_id (str): found host_id in quarantine or detect
        """
        try:
            response = self.host_api.perform_action(ids=host_id, action_name='contain', note='Containment triggered by VMRAY Connector!')
            if len(response["body"]["errors"]) > 0:
                self.log.error(f"Host {host_id} cannot be contained Error : {response['errors'][0]['message']}")
                return
            self.log.info(f"Host {host_id} has been contained")
        except:
            self.log.error(f"Cannot contain host {host_id}")
        return
   
        
    def check_ioc(self, type: str, value: str) -> bool:
        """Check ioc exist or not
        
        Args:
            type (str): type of IOC (domain, ip, sha256)
            value (str): value of IOC
        
        Returns: True if ioc exist else False
        """
        try:
            response = self.ioc_api.indicator_search(filter=f"type:'{type}'+value:'{value}'")
            print(response)
            if len(response["body"]["resources"]) == 0:
                return False
        except:
            self.log.error(f"Cannot check ioc {type}:{value}")
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
                if len(response['body']['errors']) > 0:
                    self.log.error(f"Cannot create ioc {sample.sample_sha256} because of {response['body']['errors']}")
            
            # create iocs with ipv4 found in vmray result
            for ip in sample.vmray_result['ipv4']:
                if not self.check_ioc(type="ipv4", value=ip):
                    response = self.ioc_api.indicator_create(action='detect', 
                                                             type='ipv4', 
                                                             value=ip,
                                                             applied_globally=True,
                                                             platforms=['mac','windows','linux'],
                                                             severity='high',
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if len(response['body']['errors']) > 0:
                        self.log.error(f"Cannot create ioc {ip} because of {response['body']['errors']}")
                 
            # create iocs with sha256 found in vmray result       
            for found_sha256 in sample.vmray_result['sha256']:
                if not self.check_ioc(type="sha256", value=found_sha256):
                    response = self.ioc_api.indicator_create(action='prevent',
                                                             type='sha256', 
                                                             value=sample.sample_sha256, 
                                                             applied_globally=True,
                                                             severity='high',
                                                             platforms=['mac','windows','linux'],
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if len(response['body']['errors']) > 0:
                        self.log.error(f"Cannot create ioc {found_sha256} because of {response['body']['errors']}")
                        
            # create iocs with domain found in vmray result
            for domain in sample.vmray_result['domain']:
                if not self.check_ioc(type="domain", value=domain):
                    response = self.ioc_api.indicator_create(action='detect', 
                                                             type='domain', 
                                                             value=domain,
                                                             applied_globally=True,
                                                             platforms=['mac','windows','linux'],
                                                             severity='high',
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if len(response['body']['errors']) > 0:
                        self.log.error(f"Cannot create ioc {domain} because of {response['body']['errors']}")
        except Exception as err:
            self.log.error(f"Cannot create ioc {sample.sample_sha256} because of {err}")
         
    
    def find_ioc_devices(self, sample: Sample) -> list[str]:
        """Find devices that ran on given sample's IOCs

        Args:
            sample (Sample): sample object

        Returns:
            list[str]: list of host ids
        """
        host_ids = []
        if not self.check_ioc(type="sha256", value=sample.sample_sha256):
            response = self.ioc_api.devices_ran_on(type='sha256', value=sample.sample_sha256)
            if len(response['body']['errors']) > 0:
                self.log.error(f"Cannot get host infos for ioc {sample.sample_sha256} because of {response['body']['errors']}")
            else:
                host_ids.extend(response['body']['resources'])
                
        for found_sha256 in sample.vmray_result['sha256']:
            if not self.check_ioc(type="sha256", value=found_sha256):
                response = self.ioc_api.devices_ran_on(policy='detect', type='sha256', value=found_sha256)
                if len(response['body']['errors']) > 0:
                    self.log.error(f"Cannot get host infos for ioc {found_sha256} because of {response['body']['errors']}")
                else:
                    host_ids.extend(response['body']['resources'])
        return host_ids
        
        
    def open_case(self, sample: Sample=None, message: str= None, title: str= None) -> None:
        '''Open case for given sample
        
        ##TODO : Couldn't be tested because of lack of permissions. If any suggestion or fix please open issue
        '''
        try:
            response = self.message_center_api.create_case(user_uuid=self.config.CASE_USER, title=title, message= message)
            if len(response['body']['errors']) > 0:
                self.log.error(f"Cannot create case! ERROR: {response['body']['errors']}")
        except:
            self.log.error(f"Cannot create case for {sample.sample_sha256}")
        pass

    def update_quarantine(self, quarantine_id: str, comment: str, action: str) -> None:
        """Update quarantine with given id

        Args:
            quarantine_id (str): quarantine id in crowdstrike
            comment (str): comment to add to quarantine object
            action (str): action to take on quarantine object
        """
        try:
            response = self.quarantine_api.update_quarantined_detects_by_id(ids=quarantine_id, comment=comment, action=action)
            if response["status_code"] != 200 and len(response['body']['errors']) > 0:
                self.log.error(f"Cannot update quarantine {quarantine_id} because of {response['body']['errors']}")    

        except:
            self.log.error(f"Cannot update quarantine {quarantine_id}")

    
    def update_detection(self, detection_id: str, comment: str, status: str) -> None:
        """Update detection with given id

        Args:
            detection_id (str): detection id in crowdstrike
            comment (str): comment to add to detection object
            status (str): status to set on detection object
        """
        show_in_ui = False
        if status != 'false_positive':
            show_in_ui = True
        try:
            response = self.detect_api.update_detects_by_ids(ids=detection_id, comment=comment, status=status, show_in_ui=show_in_ui)
            if response["status_code"] != 200 and len(response['body']['errors']) > 0:
                self.log.error(f"Cannot update detection {detection_id} because of {response['body']['errors']}")    
        except:
            self.log.error(f"Cannot update detection {detection_id}")

    def export_host_from_detection(self, detection: ConnectorDetect):
        """Export host from given detection
        
        Args:
            detection (ConnectorDetect): detection object
            
        Returns: 
            host_id (str): host id of given detection
        """
        if detection.host_id is None:
            return None
        return detection.host_id