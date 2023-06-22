import io
from random import sample
from re import sub
from socket import timeout
import time
import ipaddress
from datetime import datetime

from urllib.parse import urlparse
import json

from vmray.rest_api import VMRayRESTAPI

from config.general_conf import GeneralConfig, VERDICT
from config.vmray_conf import VMRayConfig, JOB_STATUS
from lib.Sample import Sample


class VMRay:
    """
        Wrapper class for VMRayRESTAPI modules and functions.
        Import this class to submit samples and retrieve reports.
    """

    def __init__(self, log):
        """
        Initialize, authenticate and healthcheck the VMRay instance, use VMRayConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.log = log
        self.config = VMRayConfig

        self.authenticate()
        self.healthcheck()

    def healthcheck(self):
        """
        Healtcheck for VMRay REST API, uses system_info endpoint
        :raise: When healtcheck error occured during the connection wih REST API
        :return: boolean status of VMRay REST API
        """
        self.log.debug("healthcheck function is invoked")

        method = "GET"
        url = "/rest/system_info"

        try:
            self.api.call(method, url)
            self.log.info("VMRAY Healthcheck is successfull.")
            return True
        except Exception as err:
            self.log.error(f"Healthcheck failed. Error : {err}")
            raise

    def authenticate(self):
        """
        Authenticate the VMRay REST API
        :raise: When API Key is not properly configured
        :return: void
        """
        self.log.debug("authenticate function is invoked")

        try:
            self.api = VMRayRESTAPI(self.config.URL, self.config.API_KEY,
                                    self.config.SSL_VERIFY, self.config.CONNECTOR_NAME)
            self.log.debug(
                f"Successfully authenticated the VMRay {self.config.API_KEY_TYPE} API")
        except Exception as err:
            self.log.error(err)
            raise

    def get_sample_summary(self, identifier, sample_id=False):
        """
        Retrieve sample summary from VMRay database with sample_id or sha256 hash value
        :param identifier: sample_id or sha256 hash value to identify submitted sample
        :param sample_id: boolean value to determine which value (sample_id or sha256) is passed to function
        :return: dict object which contains summary data about sample
        """
        self.log.debug("get_sample function is invoked")

        method = "GET"
        if sample_id:
            url = f"/rest/sample/{identifier}".format(identifier)
        else:
            url = f"/rest/sample/sha256/{identifier}".format(identifier)
        try:
            response = self.api.call(method, url)
            if len(response) == 0:
                self.log.debug(
                    f"Sample {identifier} couldn't be found in VMRay database.".format(identifier))
                return None
            else:
                self.log.debug(
                    f"Sample {identifier} retrieved from VMRay".format(identifier))
                return response[0]
        except Exception as err:
            self.log.debug(
                "Sample {} couldn't be found in VMRay database. Error: {}".format(identifier, err))
            return None

    def get_sample_iocs(self, sample_data):
        """
        Retrieve IOC values from VMRay
        :param sample_data: dict object which contains summary data about the sample
        :return iocs: dict object which contains IOC values according to the verdict
        """
        self.log.debug("get_sample_iocs function is invoked")

        sample_id = sample_data["sample_id"]
        iocs = {}

        for key in GeneralConfig.SELECTED_VERDICTS:
            try:
                url = f"/rest/sample/{sample_id}/iocs/verdict/{key}"
                response = self.api.call("GET", url)

                iocs[key] = response
                self.log.debug(
                    f"IOC reports for {sample_id} retrieved from VMRay".format(sample_id))
            except Exception as err:
                self.log.error(err)

        return iocs

    def get_sample_vtis(self, sample_id):
        """
        Retrieve VTI(Vmray Threat Identifier) values from VMRay
        :param sample_id: sample_id to identify submitted sample
        :return response: dict object which contains VTI values according to the verdict
        """
        self.log.debug("get_sample_vtis function is invoked")

        try:
            url = f"/rest/sample/{sample_id}/vtis"
            response = self.api.call("GET", url)
            self.log.debug(
                f"VTI reports for {sample_id} retrieved from VMRay".format(sample_id))
            return response
        except Exception as err:
            self.log.debug(
                f"VTI reports for {sample_id} couldn't be retrieved from VMRay".format(sample_id))
            self.log.error(err)
            return None

    def parse_sample_summary_data(self, sample_summary):
        """
            Parse sample data to get required fields

        Args:
            sample (): dict object which contains summary data about the sample

        Returns:
            sample : dict object which contains parsed data about sample
        """
        self.log.debug("parse_sample_data function is invoked")

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
            "sample_classification",
            "sample_thread_name",
        ]
        if sample_summary is not None:
            if type(sample_summary) == type(list):
                sample_summary = sample_summary[0]
            for key in keys:
                if key in sample_summary:
                    sample_data[key] = sample_summary[key]
        return sample_data

    def parse_sample_iocs(self, iocs):
        """
            Parse and extract process, file and network IOC values about the sample
            :param iocs: dict object which contains raw IOC data about the sample
            :return ioc_data: dict object which contains parsed/extracted process, file and network IOC values
        """
        self.log.debug("parse_sample_iocs function is invoked")

        ioc_data = {}

        process_iocs = self.parse_process_iocs(iocs)
        file_iocs = self.parse_file_iocs(iocs)
        network_iocs = self.parse_network_iocs(iocs)
        registry_iocs = self.parse_registry_iocs(iocs)

        for key in process_iocs:
            ioc_data[key] = process_iocs[key]

        for key in file_iocs:
            ioc_data[key] = file_iocs[key]

        for key in network_iocs:
            ioc_data[key] = network_iocs[key]

        for key in registry_iocs:
            ioc_data[key] = registry_iocs[key]

        return ioc_data

    def parse_process_iocs(self, iocs):
        """
        Parse and extract Process IOC values (cmd_line, image_name) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return process_iocs: dict object which contains image_names and cmd_line parameters as IOC values
        """
        self.log.debug("parse_process_iocs function is invoked")

        process_iocs = {}
        cmd_lines = set()
        image_names = set()

        for ioc_type in iocs:
            processes = iocs[ioc_type]["iocs"]["processes"]
            for process in processes:
                if process["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    cmd_lines.add(process["cmd_line"])
                    image_names.update(process["image_names"])

        process_iocs["cmdline"] = cmd_lines
        process_iocs["image_name"] = image_names

        return process_iocs

    def parse_file_iocs(self, iocs):
        """
        Parse and extract File IOC values (sha256, file_name) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return file_iocs: dict object which contains sha256 hashes and file_names as IOC values
        """
        self.log.debug("parse_file_iocs function is invoked")

        file_iocs = {}
        sha256 = set()
        filenames = set()

        for ioc_type in iocs:
            files = iocs[ioc_type]["iocs"]["files"]
            for file in files:
                if file["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    if "Ransomware" not in file["classifications"]:
                        for file_hash in file["hashes"]:
                            sha256.add(file_hash["sha256_hash"])
                        filenames.update(file["filenames"])

        file_iocs["sha256"] = sha256
        file_iocs["file_name"] = filenames

        return file_iocs

    def parse_registry_iocs(self, iocs):
        """
        Parse and extract Registry IOC value (reg_key_name) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return registry_iocs: dict object which contains reg_keys as IOC values
        """
        self.log.debug("parse_registry_iocs function is invoked")

        registry_iocs = {}
        registry_keys = set()

        for ioc_type in iocs:
            registry = iocs[ioc_type]["iocs"]["registry"]
            for reg in registry:
                if reg["verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    if "reg_key_name" in reg.keys():
                        registry_keys.add(reg["reg_key_name"])

        registry_iocs["reg_key"] = registry_keys

        return registry_iocs

    def parse_network_iocs(self, iocs):
        """
        Parse and extract Network IOC values (domain, IPV4) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return network_iocs: dict object which contains domains and IPV4 addresses as IOC values
        """
        self.log.debug("parse_network_iocs function is invoked")

        network_iocs = {}
        domains = set()
        ip_addresses = set()

        for ioc_type in iocs:
            ips = iocs[ioc_type]["iocs"]["ips"]
            for ip in ips:
                domains.update(ip["domains"])
                ip_addresses.add(ip["ip_address"])

            urls = iocs[ioc_type]["iocs"]["urls"]
            for url in urls:
                ip_addresses.update(url["ip_addresses"])
                for original_url in url["original_urls"]:
                    try:
                        ipaddress.ip_address(urlparse(original_url).netloc)
                        ip_addresses.add(urlparse(original_url).netloc)
                    except Exception as err:
                        domains.add(urlparse(original_url).netloc)

        network_iocs["domain"] = domains
        network_iocs["ipv4"] = ip_addresses

        return network_iocs

    def submit_sample(self, sample:Sample):
        """
            Submit sample to VMRay Sandbox to analyze
            :param files: list of file paths which downloaded from CarbonBlack UBS
            :return submissions: dict object which contains submission_id and sample_id
        """
        self.log.debug("submit_samples function is invoked")

        method = "POST"
        url = "/rest/sample/submit"

        params = {}
        params["comment"] = self.config.SUBMISSION_COMMENT
        params["tags"] = ",".join(self.config.SUBMISSION_TAGS)
        params["user_config"] = json.dumps({"timeout": self.config.ANALYSIS_TIMEOUT})
        params["analyzer_mode"] = self.config.DEFAULT_ANALYZER_MODE.value
        
        try:
            with io.open(sample.unzipped_path, "rb") as file_object:
                params["sample_file"] = file_object
                try:
                    response = self.api.call(method, url, params=params)
                except Exception as err:
                    self.log.error("Error while submitting sample to VMRay Sandbox: {}".format(err))
                
                if len(response["errors"]) > 0:
                    sample.vmray_submit_successfully = False
                    for error in response["errors"]:
                        self.log.error("VMray Error while submitting sample : {}".format(error))
                
                sample.vmray_submission_id = response["submissions"][0]["submission_id"]
                if "sample_id" in response["submissions"][0].keys():
                    sample.vmray_sample_id = response["submissions"][0]["sample_id"]
                sample.vmray_submit_successfully = True
        except Exception as err:
            self.log.error("Error while submitting sample to VMRay Sandbox: {}".format(err))
            sample.vmray_submit_successfully = False
            sample.vmray_submission_id = None
            sample.vmray_sample_id = None
            
    
    def wait_submissions(self, submitted_samples:list[Sample]):
        """
        Wait for the submission analyses to finish
        :param submissions: list of Sample objects which contains submission_id and sample_id
        """
        self.log.debug("wait_submissions function is invoked")

        method = "GET"
        url = "/rest/submission/{}"

        # Creating submission_objects list with submission info
        # Adding timestamp and error_count for checking status and timeouts
        submission_objects = []
        for submission in submitted_samples:
            submission_objects.append({"sample": submission,
                                       "timestamp": None,
                                       "error_count": 0})

        self.log.info(f"Waiting {len(submission_objects)} submission jobs to finish")

        # Wait for all submissions to finish or exceed timeout
        while len(submission_objects) > 0:
            time.sleep(VMRayConfig.ANALYSIS_JOB_TIMEOUT / 10)
            for submission_object in submission_objects:
                try:
                    if not self.check_submission_error(submission_object['sample'].vmray_submission_id):
                        raise Exception("Submission error")
                    
                    response = self.api.call(method, url.format(submission_object["sample"].vmray_submission_id))
                    # If submission is finished, return submission info and process sample report,IOC etc
                    if response["submission_finished"]:
                        self.add_sample_results(submission_object['sample'])
                        submission_object['sample'].vmray_submission_finished = True
                        submission_objects.remove(submission_object)
                        self.log.info(f"Submission job {submission_object['sample'].vmray_submission_id} finished" )

                    # If submission is not finished and timer is not set, start timer to check timeout
                    elif submission_object["timestamp"] is None:
                        if self.is_submission_started(submission_object["sample"].vmray_submission_id):
                            submission_object["timestamp"] = datetime.now()

                    # If timer is set, check configured timeout and return status as not finished
                    elif (datetime.now() - submission_object["timestamp"]).seconds >= VMRayConfig.ANALYSIS_JOB_TIMEOUT:
                        self.log.error(f"Submission job {submission_object['sample'].vmray_submission_id} exceeded the configured time threshold.")
                        submission_object['sample'].vmray_submission_finished = False
                        submission_objects.remove(submission_object)
                        continue

                except Exception as err:
                    self.log.error(str(err).split(":")[0])

                    # If 5 errors are occured, return status as not finished else try again
                    if submission_object["error_count"] >= 5:
                        submission_object['sample'].vmray_submission_finished = False
                    else:
                        submission_object["error_count"] += 1

        self.log.info("Submission jobs finished")

    def is_submission_started(self, submission_id):
        """
        Check if submission jobs are started
        :param submission_id: id value of submission
        :return status: boolean value of status
        """
        self.log.debug("is_submission_started function is invoked")

        method = "GET"
        url = "/rest/job/submission/{}"

        try:
            response = self.api.call(method, url.format(submission_id))
            self.log.debug(f"Submission {submission_id} jobs successfully retrieved from VMRay")
            for job in response:
                if job["job_status"] == JOB_STATUS.INWORK.value:
                    self.log.debug(f"At least one job is started for submission {submission_id}")
                    return True
            self.log.debug(f"No job has yet started for submission {submission_id}")
            return False
        except Exception as err:
            self.log.debug(f"Submission {submission_id} jobs couldn't be retrieved from VMRay. Error: {err}")
            return False

    def add_sample_results(self, sample):
        sample_summary = self.get_sample_summary(sample.sample_sha256)
        if sample_summary is None:
            return
        sample_metadata = self.parse_sample_summary_data(sample_summary)
        sample.vmray_metadata = sample_metadata    
        sample_ioc = self.get_sample_iocs(sample_summary)
        parsed_sample_ioc = self.parse_sample_iocs(sample_ioc)
        sample.vmray_result = parsed_sample_ioc
    
    def get_submission_analyses(self, submission_id):
        """
        Retrieve analyses details of submission
        :param submission_id: id value of the submission
        :return: dict object which contains analysis information about the submission
        """
        self.log.debug("get_submission_analyses function is invoked")

        method = "GET"
        url = f"/rest/analysis/submission/{submission_id}"
        try:
            response = self.api.call(method, url)
            self.log.debug(f"Submission {submission_id} analyses successfully retrieved from VMRay")
            return response
        except Exception as err:
            self.log.debug(f"Submission {submission_id} analyses couldn't retrieved from VMRay. Error: {err}")
            return None   
    
    def check_submission_error(self, submission):
        """
        Check and log any analysis error in finished submissions
        :param submissions: list of submission_id's
        :return: void
        """
        self.log.debug("check_submission_error function is invoked")
        analyses = self.get_submission_analyses(submission)
        if analyses is not None:
            for analysis in analyses:
                if analysis["analysis_severity"] == "error":
                    self.log.error(f"Analysis {analysis['analysis_id']} for submission {submission['submission_id']} has error: {analysis['analysis_result_str']}")
                    return False
        else:
            return False
        return True
