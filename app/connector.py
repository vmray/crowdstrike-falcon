"""Entry point for the VMRay Connector for CrowdStrike Falcon.

Orchestrates the full pipeline: fetching quarantines and detections from
CrowdStrike, checking and submitting samples to VMRay, and writing analysis
results (comments, IOC indicators) back to CrowdStrike.
"""

import logging
import pathlib
import time
import os

from config.general_conf import GeneralConfig, RUNTIME_MODE, VERDICT
from config.crowdstrike_conf import CrowdStrikeConfig, DATA_SOURCE
from config.vmray_conf import VMRayConfig
from config.constants import QUARANTINE_ACTION_UNRELEASE, QUARANTINE_ACTION_RELEASE
from lib.VMRay import VMRay
from lib.CrowdStrike import CrowdStrike, Sample

logger = logging.getLogger(__name__)


def _setup_logging():
    """Configure the root logger with a file handler and a stream handler."""
    log_format = '%(asctime)s [PID %(process)d] %(name)s:%(lineno)d %(levelname)s %(message)s'
    logging.basicConfig(
        level=GeneralConfig.LOG_LEVEL,
        format=log_format,
        handlers=[
            logging.FileHandler(GeneralConfig.LOG_FILE_PATH),
            logging.StreamHandler(),
        ],
    )


def run():
    """Execute one full connector run.

    Performs the following steps in order:

    1. Ensures the log and download directories exist.
    2. Configures logging.
    3. Authenticates CrowdStrike and VMRay API clients.
    4. Fetches quarantines and/or detections from the configured data sources.
    5. Checks each unique hash against the VMRay database; caches results or
       queues for (re)submission as appropriate.
    6. Downloads, submits, and waits for VMRay analysis of new samples.
    7. For each successfully analysed sample:

       - Posts structured comments to matched detections (if configured).
       - Creates CrowdStrike IOCs for malicious verdicts.
       - Updates quarantine disposition and adds a comment (if configured).

    8. Cleans up downloaded ZIP and extracted sample files.
    """
    GeneralConfig.LOG_DIR.mkdir(parents=True, exist_ok=True)
    GeneralConfig.LOG_FILE_PATH.touch(exist_ok=True)
    CrowdStrikeConfig.DOWNLOAD_DIR_PATH.mkdir(parents=True, exist_ok=True)
    _setup_logging()

    logger.info("VMRay Connector for CrowdStrike Falcon starting")

    # --- API client initialisation ---
    try:
        cs = CrowdStrike()
    except Exception as e:
        logger.error(f"Failed to initialise CrowdStrike API client: {e}")
        return

    try:
        vmray = VMRay()
    except Exception as e:
        logger.error(f"Failed to initialise VMRay API client: {e}")
        return

    quarantines = []
    detects = []
    hash_list = set()
    sample_list = []
    found_samples = []
    download_samples = []
    resubmit_samples = []
    quarantine_hashes = set()
    detect_hashes = set()

    # --- Fetch from CrowdStrike ---
    if DATA_SOURCE.QUARANTINE in CrowdStrikeConfig.SELECTED_DATA_SOURCES:
        try:
            quarantines.extend(cs.get_quarantines())
            quarantine_hashes.update(cs.extract_hash_from_quarantines(quarantines))
            logger.info(f"Quarantines: retrieved {len(quarantines)} item(s), {len(quarantine_hashes)} unique hash(es)")
            hash_list.update(quarantine_hashes)
        except Exception as e:
            logger.error(f"Failed to retrieve quarantines from CrowdStrike: {e}")

    if DATA_SOURCE.ALERT in CrowdStrikeConfig.SELECTED_DATA_SOURCES:
        try:
            detects.extend(cs.get_alerts())
            detect_hashes.update(cs.extract_hashes_from_alerts(detects))
            logger.info(f"Detections: retrieved {len(detects)} alert(s), {len(detect_hashes)} unique hash(es)")
            hash_list.update(detect_hashes)
        except Exception as e:
            logger.error(f"Failed to retrieve detections from CrowdStrike: {e}")

    if not hash_list:
        if CrowdStrikeConfig.SELECTED_DATA_SOURCES:
            sources = ', '.join(s.value for s in CrowdStrikeConfig.SELECTED_DATA_SOURCES)
            logger.warning(f"No hashes found across configured data sources ({sources}) — nothing to process")
        else:
            logger.warning("No data sources configured — nothing to process")
        return

    for sample_hash in hash_list:
        sample_list.append(Sample(sample_sha256=sample_hash))

    logger.info(f"Number of samples to process: {len(hash_list)}")

    try:
        # --- VMRay database lookup ---
        for sample in sample_list:
            sample_summary = vmray.get_sample_summary(sample.sample_sha256)
            if sample_summary is not None:
                sample_metadata = vmray.parse_sample_summary_data(sample_summary)
                verdict_str = sample_metadata.get('sample_verdict', '')
                if verdict_str == VERDICT.MALICIOUS.value:
                    sample.vmray_verdict = VERDICT.MALICIOUS
                elif verdict_str == VERDICT.SUSPICIOUS.value:
                    sample.vmray_verdict = VERDICT.SUSPICIOUS
                else:
                    sample.vmray_verdict = VERDICT.CLEAN

                if VMRayConfig.RESUBMIT and sample.vmray_verdict in VMRayConfig.RESUBMISSION_VERDICTS:
                    logger.info(f"Sample {sample.sample_sha256} found in VMRay (verdict={sample.vmray_verdict.value}) — queued for resubmission")
                    resubmit_samples.append(sample)
                else:
                    logger.info(f"Sample {sample.sample_sha256} found in VMRay (verdict={sample.vmray_verdict.value}) — no resubmission")
                    sample.downloaded_successfully = True
                    sample.vmray_submit_successfully = True
                    sample.vmray_submission_finished = True
                    try:
                        vmray.add_sample_results(sample, sample_summary)
                    except Exception as e:
                        logger.error(f"Failed to populate results for {sample.sample_sha256}: {e}", exc_info=True)
                    found_samples.append(sample)
            else:
                download_samples.append(sample)

        if found_samples:
            logger.info(f"{len(found_samples)} sample(s) found from VMRay database")
        if resubmit_samples:
            logger.info(f"{len(resubmit_samples)} sample(s) found in VMRay database but scheduled for resubmission")

        download_samples.extend(resubmit_samples)

        # --- Download and submit ---
        if download_samples:
            logger.info(f"{len(download_samples)} sample(s) to download and submit to VMRay")
            for sample in download_samples:
                cs.download_malware_sample(sample)

        for sample in download_samples:
            if sample.downloaded_successfully:
                vmray.submit_sample(sample)

        vmray.wait_submissions(download_samples)
        found_samples.extend(download_samples)

        # --- Write results back to CrowdStrike ---
        for sample in found_samples:
            detection_objs = [d for d in detects if d.included_sha256 == sample.sample_sha256]
            quarantine_obj = next((q for q in quarantines if q.sha256_hash == sample.sample_sha256), None)

            if not sample.downloaded_successfully:
                logger.warning(f"Skipping actions for {sample.sample_sha256}: download failed")
                continue
            if not sample.vmray_submit_successfully:
                logger.warning(f"Skipping actions for {sample.sample_sha256}: VMRay submission failed")
                continue
            if not sample.vmray_submission_finished:
                logger.warning(f"Skipping actions for {sample.sample_sha256}: VMRay analysis timed out")
                continue
            if not sample.vmray_metadata:
                logger.warning(f"Skipping actions for {sample.sample_sha256}: no VMRay metadata available")
                continue

            logger.info(
                f"Processing results for {sample.sample_sha256}: verdict={sample.vmray_verdict.value}, "
                f"detections={len(detection_objs)}, quarantine={'yes' if quarantine_obj else 'no'}"
            )

            if CrowdStrikeConfig.COMMENT_TO_DETECTION and detection_objs:
                comments = cs.build_detection_comments(sample)
                for detection in detection_objs:
                    for comment in comments:
                        cs.update_alert(detection.composite_id, comment=comment)
                logger.info(
                    f"Posted comment(s) to {len(detection_objs)} detection(s) for {sample.sample_sha256}"
                )
            elif not CrowdStrikeConfig.COMMENT_TO_DETECTION:
                logger.warning("COMMENT_TO_DETECTION is disabled. Enable it in crowdstrike_conf.py.")
            else:
                logger.info("No detection(s) to comment.")

            if sample.vmray_verdict == VERDICT.MALICIOUS:
                cs.create_ioc(sample=sample)
                logger.info(f"IOC creation completed for {sample.sample_sha256}")

            if quarantine_obj is not None and CrowdStrikeConfig.COMMENT_TO_QUARANTINE:
                webif_url = sample.vmray_metadata.get('sample_webif_url', '')
                if sample.vmray_verdict == VERDICT.MALICIOUS:
                    cs.update_quarantine(quarantine_obj.quarantine_id,
                                         comment=f"Quarantine is malicious. See result on {webif_url}",
                                         action=QUARANTINE_ACTION_UNRELEASE)
                elif sample.vmray_verdict == VERDICT.SUSPICIOUS:
                    cs.update_quarantine(quarantine_obj.quarantine_id,
                                         comment=f"Quarantine is suspicious. See result on {webif_url}",
                                         action=QUARANTINE_ACTION_UNRELEASE)
                elif sample.vmray_verdict == VERDICT.CLEAN:
                    cs.update_quarantine(quarantine_obj.quarantine_id,
                                         comment='Quarantine file is clean.',
                                         action=QUARANTINE_ACTION_RELEASE)
            elif not CrowdStrikeConfig.COMMENT_TO_QUARANTINE:
                logger.warning("COMMENT_TO_QUARANTINE is disabled. Enable it in crowdstrike_conf.py.")
            else:
                logger.info("No quarantine to comment and take action.")
    except Exception as e:
        logger.error(f"Error occurred while processing: {e}", exc_info=True)

    finally:
        if download_samples:
            for sample in download_samples:
                if sample.zipped_path and pathlib.Path(sample.zipped_path).exists():
                    try:
                        os.remove(sample.zipped_path)
                    except OSError as e:
                        logger.warning(f"Failed to remove {sample.zipped_path}: {e}")
                if sample.unzipped_path and pathlib.Path(str(sample.unzipped_path)).exists():
                    try:
                        os.remove(str(sample.unzipped_path))
                    except OSError as e:
                        logger.warning(f"Failed to remove {sample.unzipped_path}: {e}")
            logger.info("Files cleanup completed.")

    logger.info("VMRay connector run completed.")


if __name__ == "__main__":  # pragma: no cover
    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            try:
                run()
            except Exception as err:
                logger.error(f"Connector Run failed: {err}. Retrying...", exc_info=True)
                continue
            logger.info(f"Sleeping {GeneralConfig.TIME_SPAN}s until next run")
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
