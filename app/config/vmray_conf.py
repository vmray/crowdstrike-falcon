from enum import Enum
import os
from config.general_conf import VERDICT
# VMRay API Key types enum


class VMRAY_API_KEY_TYPE(Enum):
    REPORT = 0
    VERDICT = 1

# VMRay job status
class JOB_STATUS(Enum):
    QUEUED = "queued"
    INWORK = "inwork"


# VMRay Configuration
class VMRayConfig:
    # VMRay API Key type setting
    API_KEY_TYPE = VMRAY_API_KEY_TYPE.REPORT

    # VMRay Report or Verdict API KEY
    API_KEY = os.environ.get("VMRAY_API_KEY", "")

    # VMRay REST API URL (override via VMRAY_BASE_URL env var)
    URL = os.environ.get("VMRAY_BASE_URL") or "https://eu.cloud.vmray.com"

    # User Agent string for VMRay Api requests
    # Defined for further use
    CONNECTOR_NAME = "CrowdStrikeCloudConnector"

    # SSL Verification setting for self-signed certificates
    SSL_VERIFY = True

    # VMRay Submission Comment
    SUBMISSION_COMMENT = "Sample from VMRay CrowdStrike Connector"

    # VMRay submission tags (Can't contain space)
    SUBMISSION_TAGS = ["CrowdStrike"]

    # VMRay analysis timeout value (seconds)
    ANALYSIS_TIMEOUT = 120

    # VMRay analysis job timeout for wait_submissions
    ANALYSIS_JOB_TIMEOUT = 3600

    # Resubmission status which has been already analyzed by VMRay
    RESUBMIT = True

    # Selected verdicts to resubmit evidences
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]
