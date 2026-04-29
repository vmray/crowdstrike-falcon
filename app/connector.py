import logging as log
import pathlib
import time
import os

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
    log_format = '[%(asctime)s] [<pid:%(process)d> %(filename)s:%(lineno)s %(funcName)s] %(levelname)s %(message)s'
    log.basicConfig(level=GeneralConfig.LOG_LEVEL, format=log_format, handlers=[
        log.FileHandler(GeneralConfig.LOG_FILE_PATH),
        log.StreamHandler()
    ])
    log.info(
        '[CONNECTOR.PY] Started VMRAY Analyzer Connector for CrowdStrike Falcon')

    # Initializing and authenticating api instances
    try:
        cs = CrowdStrike(log)
    except Exception as e:
        log.error(f"Failed to initialize CrowdStrike API client: {e}")
        return
    try:
        vmray = VMRay(log)
    except Exception as e:
        log.error(f"Failed to initialize VMRay API client: {e}")
        return

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
            quarantine_hashes = cs.extract_hash_from_quarantines(quarantines)
            log.info(f"Extracted hash from quarantines: {quarantine_hashes}")
            hash_list.update(quarantine_hashes)
        except Exception as e:
            log.error(
                f"An error occurred while retrieving quarantines from CrowdStrike: {e}")

    if DATA_SOURCE.DETECT in CrowdStrikeConfig.SELECTED_DATA_SOURCES:
        # Retrieving detects from CrowdStrike
        try:
            detects.extend(cs.get_alerts())
            detect_hashes = cs.extract_hashes_from_alerts(detects)
            log.info(f"Extracted hash from detects: {detect_hashes}")
            hash_list.update(detect_hashes)
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
                
                # set sample verdict according to vmray verdict
                verdict_str = sample_metadata.get('sample_verdict', '')
                if verdict_str == VERDICT.MALICIOUS.value:
                    sample.vmray_verdict = VERDICT.MALICIOUS
                elif verdict_str == VERDICT.SUSPICIOUS.value:
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
                    sample.vmray_submit_successfully = True
                    sample.vmray_submission_finished = True
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
            quarantine_obj = None

            for detection in detects:
                if detection.included_sha256 == sample.sample_sha256:
                    detection_objs.append(detection)

            for quarantine in quarantines:
                if quarantine.sha256_hash == sample.sample_sha256:
                    quarantine_obj = quarantine
                    break

            # check if sample downloaded, submitted, and analysis finished
            if not sample.downloaded_successfully:
                log.warning(f"Skipping actions for {sample.sample_sha256}: download failed")
                continue
            if not sample.vmray_submit_successfully:
                log.warning(f"Skipping actions for {sample.sample_sha256}: VMRay submission failed")
                continue
            if not sample.vmray_submission_finished:
                log.warning(f"Skipping actions for {sample.sample_sha256}: VMRay analysis did not finish")
                continue
            if not sample.vmray_metadata:
                log.warning(f"Sample {sample.sample_sha256} has no VMRay metadata, skipping actions")
                continue

            webif_url = sample.vmray_metadata.get('sample_webif_url', '')
            classifications = sample.vmray_result.get('classifications', set())
            threat_names_set = sample.vmray_result.get('threat_names', set())

            # add comment to detection
            if CrowdStrikeConfig.COMMENT_TO_DETECTION:
                for detection in detection_objs:
                    if sample.vmray_verdict == VERDICT.MALICIOUS:
                        cs.update_alert(detection.composite_id,
                                        comment=f"Vmray sample validation verdict: Malicious. Detailed analysis can be found on VMRAY with the link {webif_url}")
                        if len(list(classifications)) > 0:
                            threat_classification = "\n".join(classifications)
                            cs.update_alert(detection.composite_id,
                                            comment=f"Threat Classification : {threat_classification}")
                        if len(list(threat_names_set)) > 0:
                            threat_names = "\n".join(threat_names_set)
                            cs.update_alert(detection.composite_id,
                                            comment=f"Threat Name : {threat_names}")
                    if sample.vmray_verdict == VERDICT.SUSPICIOUS:
                        cs.update_alert(detection.composite_id,
                                        comment=f"Vmray sample validation verdict: Suspicious. detailed analysis can be found on VMRAY with the link {webif_url}")
                        if len(list(classifications)) > 0:
                            threat_classification = "\n".join(classifications)
                            cs.update_alert(detection.composite_id,
                                            comment=f"Threat Classification : {threat_classification}")
                        if len(list(threat_names_set)) > 0:
                            threat_names = "\n".join(threat_names_set)
                            cs.update_alert(detection.composite_id,
                                            comment=f"Threat Name : {threat_names}")
                    if sample.vmray_verdict == VERDICT.CLEAN:
                        cs.update_alert(detection.composite_id,
                                        comment='sample is clean.')

            # create IOCs
            if sample.vmray_verdict == VERDICT.MALICIOUS:
                cs.create_ioc(sample=sample)

            # add comment to quarantine and determine status if clean release, if malicious delete, if suspicious unrelease
            if quarantine_obj is not None and CrowdStrikeConfig.COMMENT_TO_QUARANTINE:
                if sample.vmray_verdict == VERDICT.MALICIOUS:
                    cs.update_quarantine(quarantine_obj.quarantine_id,
                                         comment=f"quarantine is malicious. See result on {webif_url}",
                                         action='unrelease')
                if sample.vmray_verdict == VERDICT.SUSPICIOUS:
                    cs.update_quarantine(quarantine_obj.quarantine_id,
                                         comment=f"quarantine is suspicious. See result on {webif_url}",
                                         action='unrelease')
                if sample.vmray_verdict == VERDICT.CLEAN:
                    cs.update_quarantine(quarantine_obj.quarantine_id,
                                         comment='quarantine file is clean.',
                                         action='release')

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
            try:
                run()
            except Exception as err:
                log.error(f"Unhandled exception in run loop: {err}")
                continue
            log.info(f"Sleeping {GeneralConfig.TIME_SPAN} seconds.")
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()