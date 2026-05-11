"""CrowdStrike API configuration: credentials, endpoints, data sources, and action flags."""

from enum import Enum
import os
import pathlib
from config.general_conf import GeneralConfig
from config.constants import CS_BASE_URL


class DATA_SOURCE(Enum):
    """CrowdStrike data sources polled by the connector."""

    QUARANTINE = "Quarantine"
    ALERT = "Alert"


class CrowdStrikeConfig:
    """CrowdStrike API settings and connector action flags.

    Credentials and the base URL are loaded from environment variables so that
    sensitive values are never stored in source code.

    Attributes:
        CLIENT_ID (str): CrowdStrike OAuth2 client ID
            (env: ``CROWDSTRIKE_CLIENT_ID``).
        CLIENT_SECRET (str): CrowdStrike OAuth2 client secret
            (env: ``CROWDSTRIKE_CLIENT_SECRET``).
        BASE_URL (str): CrowdStrike API base URL
            (env: ``CROWDSTRIKE_BASE_URL``, default us-2 region).
        DOWNLOAD_DIR (pathlib.Path): Relative name of the sample download
            directory.
        DOWNLOAD_DIR_PATH (pathlib.Path): Absolute path to the sample download
            directory, resolved relative to the ``app/`` package root.
        SELECTED_DATA_SOURCES (list[DATA_SOURCE]): Data sources to poll for
            new evidence hashes.
        TIME_SPAN (int): Look-back window in seconds passed to CrowdStrike
            queries. Adds a 600 s buffer on top of ``GeneralConfig.TIME_SPAN``
            to account for clock skew.
        COMMENT_TO_DETECTION (bool): When ``True``, post VMRay analysis comments
            to matched CrowdStrike detections.
        COMMENT_TO_QUARANTINE (bool): When ``True``, post VMRay analysis comments
            and update the disposition of matched quarantine items.
    """

    CLIENT_ID = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")
    CLIENT_SECRET = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")
    BASE_URL = os.environ.get("CROWDSTRIKE_BASE_URL") or CS_BASE_URL
    DOWNLOAD_DIR = pathlib.Path("downloads")
    DOWNLOAD_DIR_PATH = pathlib.Path(__file__).parent.parent.resolve() / DOWNLOAD_DIR
    SELECTED_DATA_SOURCES = [DATA_SOURCE.ALERT, DATA_SOURCE.QUARANTINE]
    TIME_SPAN = GeneralConfig.TIME_SPAN + 600
    COMMENT_TO_DETECTION = True
    COMMENT_TO_QUARANTINE = True
