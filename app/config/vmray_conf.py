"""VMRay API configuration: credentials, submission settings, and polling behaviour."""

import os
from config.general_conf import VERDICT
from config.constants import VMRAY_BASE_URL


class VMRayConfig:
    """VMRay REST API settings and sample submission parameters.

    The API key and URL are loaded from environment variables. All other
    values can be overridden by subclassing or modifying this class directly.

    Attributes:
        API_KEY_TYPE (str): Indicates whether a ``"report"`` or ``"verdict"``
            API key is configured.
        API_KEY (str): VMRay REST API key (env: ``VMRAY_API_KEY``).
        URL (str): VMRay instance base URL
            (env: ``VMRAY_BASE_URL``, default public cloud).
        CONNECTOR_NAME (str): User-agent string sent with VMRay API requests.
        SSL_VERIFY (bool): Whether to verify the VMRay server's TLS certificate.
            Set to ``False`` only for self-signed certificate environments.
        SUBMISSION_COMMENT (str): Comment attached to every VMRay submission.
        SUBMISSION_TAGS (list[str]): Tags attached to every VMRay submission.
            Tags must not contain spaces.
        ANALYSIS_TIMEOUT (int): Per-analysis sandbox timeout in seconds passed
            via ``user_config`` at submission time.
        ANALYSIS_JOB_TIMEOUT (int): Maximum wall-clock time in seconds the
            connector will wait for a submitted analysis to finish before
            marking it as timed out.
        POLL_INTERVAL (int): Seconds to wait between polling rounds while
            waiting for submissions to complete.
        RESUBMIT (bool): When ``True``, samples already in the VMRay database
            with a verdict in ``RESUBMISSION_VERDICTS`` are re-submitted for
            fresh analysis.
        RESUBMISSION_VERDICTS (list[VERDICT]): Verdict enum members that
            trigger resubmission when ``RESUBMIT`` is ``True``.
    """

    API_KEY_TYPE = "report"
    API_KEY = os.environ.get("VMRAY_API_KEY", "")
    URL = os.environ.get("VMRAY_BASE_URL") or VMRAY_BASE_URL
    CONNECTOR_NAME = "CrowdStrikeCloudConnector"
    SSL_VERIFY = True
    SUBMISSION_COMMENT = "Sample from VMRay CrowdStrike Connector"
    SUBMISSION_TAGS = ["CrowdStrike"]
    ANALYSIS_TIMEOUT = 120
    ANALYSIS_JOB_TIMEOUT = 3600
    POLL_INTERVAL = ANALYSIS_JOB_TIMEOUT // 100
    RESUBMIT = False
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]
