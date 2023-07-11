import logging as log
import pathlib
import time
import os
from config.vmray_conf import VMRAY_API_KEY_TYPE

from config.general_conf import GeneralConfig, RUNTIME_MODE, VERDICT
from config.crowdstrike_conf import CrowdStrikeConfig, DATA_SOURCE
from config.vmray_conf import VMRayConfig
from lib.VMRay import VMRay
from lib.CrowdStrike import CrowdStrike, Sample


def run():
    if not GeneralConfig.LOG_DIR.exists():
        GeneralConfig.LOG_DIR.mkdir()

    if not GeneralConfig.LOG_FILE_PATH.exists():
        GeneralConfig.LOG_FILE_PATH.touch()

    if not CrowdStrikeConfig.DOWNLOAD_DIR_PATH.exists():
        CrowdStrikeConfig.DOWNLOAD_DIR_PATH.mkdir()

    # Configure logging
    log.basicConfig(filename=GeneralConfig.LOG_FILE_PATH,
                    format='[%(asctime)s] [<pid:%(process)d> %(filename)s:%(lineno)s %(funcName)s] %(levelname)s %(message)s',
                    level=GeneralConfig.LOG_LEVEL)
    log.info(
        '[CONNECTOR.PY] Started VMRAY Analyzer Connector for CrowdStrike Cloud')

    # Initializing and authenticating api instances
    cs = CrowdStrike(log)
    vmray = VMRay(log)

    # Creating list object for quarantines
    quarantines = []
    
    # Creating list object for detects
    detects = []
    
    # Creating set object for sha256 hash values
    hash_list = set()
    
    # Creating list object for sample objects
    sample_list = []
    
    # List of samples which found on VMRay database
    found_samples = []

    # List of samples which need to be downloaded from CrowdStrike
    download_samples = []

    # List of samples which found on VMRay database but will be resubmitted
    resubmit_samples = []

    if DATA_SOURCE.QUARANTINE in CrowdStrikeConfig.SELECTED_DATA_SOURCES:
        # Retrieving quarantine files from CrowdStrike
        try:
            quarantines.extend(cs.get_quarantines())
            hash_list.update(cs.extract_hash_from_quarantines(quarantines))
        except Exception as e:
            log.error(
                f"An error occurred while retrieving quarantines from CrowdStrike: {e}")

    if DATA_SOURCE.DETECT in CrowdStrikeConfig.SELECTED_DATA_SOURCES:
        # Retrieving detects from CrowdStrike
        try:
            detects.extend(cs.get_detects())
            hash_list.update(cs.extract_hashes_from_detects(detects))
        except Exception as e:
            log.error(
                f"An error occurred while retrieving detects from CrowdStrike: {e}")
            
    # Checking found hashes on CrowdStrike, if no hash has been found no need to proceed
    if len(hash_list) == 0:
        if len(CrowdStrikeConfig.SELECTED_DATA_SOURCES) > 0:
            log.warning(
                f"No evidence hash was found on CrowdStrike. Selected data sources: {', '.join([str(data_source.value) for data_source in CrowdStrikeConfig.SELECTED_DATA_SOURCES])}")
        else:
            log.warning("No data source was selected on CrowdStrike")
        return
        
    for sample_hash in hash_list:
        sample_list.append(Sample(sample_sha256=sample_hash))
    try:
        # Checking hash values in VMRay database
        for sample in sample_list:
            sample_summary = vmray.get_sample_summary(sample.sample_sha256)
            
            if sample_summary is not None:
                sample_metadata = vmray.parse_sample_summary_data(sample_summary)
                
                #set sample verdict acording to vmray verdict
                if sample_metadata['sample_verdict'] == 'malicious':
                    sample.vmray_verdict = VERDICT.MALICIOUS
                elif sample_metadata['sample_verdict'] == 'suspicious':
                    sample.vmray_verdict = VERDICT.SUSPICIOUS
                else:
                    sample.vmray_verdict = VERDICT.CLEAN
                    
                # If resubmission is active and sample verdicts in configured resubmission verdicts
                # Hash added into resubmit samples and re-analyzed
                if VMRayConfig.RESUBMIT and sample.vmray_verdict in VMRayConfig.RESUBMISSION_VERDICTS:
                    log.debug(f"File {sample.sample_sha256} found in VMRay database, but will be resubmitted.")
                    resubmit_samples.append(sample)
                else:
                    log.debug(f"File {sample.sample_sha256} found in VMRay database. No need to submit again.")
                    sample.downloaded_successfully = True
                    sample.submitted_successfully = True
                    sample.vmray_submit_successfully = True
                    vmray.add_sample_results(sample)
                    found_samples.append(sample)
            else:
                download_samples.append(sample)
                
        if len(found_samples) > 0:
            log.info(f"{len(found_samples)} samples found on VMRay database")

        if len(resubmit_samples) > 0:
            log.info(
                f"{len(resubmit_samples)} samples found on VMRay database, but will be resubmitted")
            
        # Combine download_samples array and resubmit_samples array for submission
        download_samples.extend(resubmit_samples)

        if len(download_samples) > 0:
            log.info(
                f"{len(download_samples)} samples need to be downloaded and submitted")
            for sample in download_samples:
                cs.download_malware_sample(sample)
        
        for sample in download_samples:
            if sample.downloaded_successfully:
                vmray.submit_sample(sample)

        #Waiting submissions
        vmray.wait_submissions(download_samples)
        found_samples.extend(download_samples)
        
        # Actions for found samples on VMRay database
        for sample in found_samples:
            # relevant detection and quarantine objects for sample
            detection_objs = []
            relevant_hosts_ids = set()
            quarantine_obj = None
            
            for detection in detects:
                if detection.included_sha256 == sample.sample_sha256:
                    detection_objs.append(detection)
                    relevant_hosts_ids.add(cs.export_host_from_detection(detection))
                
            for quarantine in quarantines:
                if quarantine.sha256_hash == sample.sample_sha256:
                    quarantine_obj = quarantine
                    relevant_hosts_ids.add(quarantine_obj.quarantine_host_id)
                    break
            
            # check if sample downloaded and submitted successfully
            if not sample.downloaded_successfully:
                if GeneralConfig.SUBMIT_OR_DOWNLOAD_ERROR_OPEN_CASE:
                    for detection in detection_objs:
                        cs.open_case(sample, detection.detect_id)
                continue
            if not sample.vmray_submit_successfully:
                if GeneralConfig.SUBMIT_OR_DOWNLOAD_ERROR_OPEN_CASE:
                    for detection in detection_objs:
                        cs.open_case(sample, detection.detect_id)
                continue
            
            # add comment to detection and detirmine status if clean closed, if suspicious in progress, if malicious in progress
            if CrowdStrikeConfig.COMMMENT_TO_DETECTION:
                for detection in detection_objs:
                    if sample.vmray_verdict == VERDICT.MALICIOUS:
                        cs.update_detection(detection.detect_id, 
                                            comment=f"sample is malicious. detailed analysis can be found on VMRAY with the link {sample.vmray_metadata['sample_webif_url']}", 
                                            status='in_progress')
                        if CrowdStrikeConfig.ADD_THREAT_CLASSIFICATION and len(list(sample.vmray_result['classifications'])) > 0:
                            cs.update_detection(detection.detect_id, 
                                                comment=f"Threat Classification : {list(sample.vmray_result['classifications'])[0]}", 
                                                status='in_progress')
                        if CrowdStrikeConfig.ADD_THREAT_NAME and len(list(sample.vmray_result['threat_names'])) > 0:
                            cs.update_detection(detection.detect_id, 
                                                comment=f"Threat Name : {list(sample.vmray_result['threat_names'])[0]}", 
                                                status='in_progress')
                    if sample.vmray_verdict == VERDICT.SUSPICIOUS:
                        cs.update_detection(detection.detect_id, 
                                            comment=f"sample is suspicious. detailed analysis can be found on VMRAY with  the link {sample.vmray_metadata['sample_webif_url']}", 
                                            status='in_progress')
                        if CrowdStrikeConfig.ADD_THREAT_CLASSIFICATION and len(list(sample.vmray_result['classifications'])) > 0:
                            cs.update_detection(detection.detect_id, 
                                                comment=f"Threat Classification : {list(sample.vmray_result['classifications'])[0]}", 
                                                status='in_progress')
                        if CrowdStrikeConfig.ADD_THREAT_NAME and len(list(sample.vmray_result['threat_names'])) > 0:
                            cs.update_detection(detection.detect_id, 
                                                comment=f"Threat Name : {list(sample.vmray_result['threat_names'])[0]}", 
                                                status='in_progress')
                    if sample.vmray_verdict == VERDICT.CLEAN:
                        cs.update_detection(detection.detect_id, 
                                            comment='sample is clean.', 
                                            status='closed')
                    
            # create IOCs
            if sample.vmray_verdict == VERDICT.MALICIOUS:
                cs.create_ioc(sample=sample)
            
            # add comment to quarantine and detirmine status if clean release, if malicious delete, if suspicious unrelease
            if CrowdStrikeConfig.COMMENT_TO_QUARANTINE:
                if sample.vmray_verdict == VERDICT.MALICIOUS:
                    cs.update_quarantine(quarantine_obj.quarantine_id, 
                                         comment=f"quarantine is malicious. See result on {sample.vmray_metadata['sample_webif_url']}", 
                                         action='unrelease')
                if sample.vmray_verdict == VERDICT.SUSPICIOUS:
                    cs.update_quarantine(quarantine_obj.quarantine_id, 
                                         comment=f"quarantine is suspicious. See result on {sample.vmray_metadata['sample_webif_url']}", 
                                         action='unrelease')
                if sample.vmray_verdict == VERDICT.CLEAN:
                    cs.update_quarantine(quarantine_obj.quarantine_id, 
                                         comment='quarantine file is clean.', 
                                         action='release')
                        
            # If sample verdict is malicious or suspicious and contain host
            if sample.vmray_verdict in CrowdStrikeConfig.CONTAIN_HOST_LEVELS and CrowdStrikeConfig.CONTAIN_HOST:
                if quarantine_obj is None and len(detection_objs) == 0:
                    log.warning(f"Sample {sample.sample_sha256} has no detection or quarantine on CrowdStrike.")
                    continue
                if len(relevant_hosts_ids) > 0:
                    for host_id in relevant_hosts_ids:
                        cs.contain_host(host_id)

            # If sample verdict is malicious or suspicious and create_case is active
            # TODO: Couldn't do POC lack of permission. if any issue occurs in here please open issue 
            if sample.vmray_verdict in CrowdStrikeConfig.CREATE_CASE_LEVELS and CrowdStrikeConfig.CREATE_CASE:
                for detection in detection_objs:
                    cs.open_case(sample, detection.detect_id)
                
            # TODO: Find another hosts that has the same sample and do actions
            if CrowdStrikeConfig.FIND_ANOTHER_HOST and sample.vmray_verdict in CrowdStrikeConfig.FIND_ANOTHER_HOST_LEVELS:
                host_ids = cs.find_ioc_devices(sample)
                for host_id in host_ids:
                    cs.contain_host(host_id)
                log.info(f"Found {len(host_ids)} devices that have the same sample.")

    except Exception as err:
        log.error(f"Unknown error occurred. Error {err}")
        
    try:
        for sample in download_samples:
            if sample.zipped_path != '' and pathlib.Path(sample.zipped_path).exists():
                os.remove(sample.zipped_path)
            if sample.unzipped_path != '' and pathlib.Path(sample.unzipped_path).exists():
                os.remove(sample.unzipped_path)
    except Exception as err:
        log.error(f"Unknown error occurred. Error {err}")

if __name__ == "__main__":
    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            run()
            log.info(f"Sleeping {GeneralConfig.TIME_SPAN} seconds.")
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
