from enum import Enum
from config.general_conf import VERDICT
# VMRay API Key types enum


class VMRAY_API_KEY_TYPE(Enum):
    REPORT = 0
    VERDICT = 1

# VMRay analyzer modes
class ANALYZER_MODE(Enum):
    REPUTATION = "reputation"
    REPUTATION_STATIC = "reputation_static"
    REPUTATION_STATIC_DYNAMIC = "reputation_static_dynamic"
    STATIC_DYNAMIC = "static_dynamic"
    STATIC = "static"


# VMRay job status
class JOB_STATUS(Enum):
    QUEUED = "queued"
    INWORK = "inwork"


# VMRay Configuration
class VMRayConfig:
    # VMRay API Key type setting
    API_KEY_TYPE = VMRAY_API_KEY_TYPE.REPORT

    # VMRay Report or Verdict API KEY
    API_KEY = "<VMRAY_API_KEY>"

    # VMRay REST API URL
    URL = "https://eu.cloud.vmray.com"

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
    ANALYSIS_JOB_TIMEOUT = 600

    # Analyzer mode for normal samples
    DEFAULT_ANALYZER_MODE = ANALYZER_MODE.REPUTATION_STATIC_DYNAMIC

    # Resubmission status which has been already analyzed by VMRay
    RESUBMIT = True

    # Selected verdicts to resubmit evidences
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]
