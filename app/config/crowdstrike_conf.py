from enum import Enum
import os
import pathlib
from config.general_conf import GeneralConfig

# CrowdStrike DataSource


class DATA_SOURCE(Enum):
    QUARANTINE = "Quarantine"
    DETECT = "Detect"

class CrowdStrikeConfig():
    # CrowdStrike Client ID
    CLIENT_ID = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")

    # CrowdStrike Client Secret
    CLIENT_SECRET = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")


    # CrowdStrike API Base URL (override via CROWDSTRIKE_BASE_URL env var)
    BASE_URL = os.environ.get("CROWDSTRIKE_BASE_URL") or "https://api.us-2.crowdstrike.com"

    # Download directory name
    DOWNLOAD_DIR = pathlib.Path("downloads")

    # Download directory path
    DOWNLOAD_DIR_PATH = pathlib.Path(
        __file__).parent.parent.resolve() / DOWNLOAD_DIR

    SELECTED_DATA_SOURCES = [DATA_SOURCE.DETECT, DATA_SOURCE.QUARANTINE]

    TIME_SPAN = GeneralConfig.TIME_SPAN + 600
    """
		###Action Configs
	"""
    # Comment to detection
    COMMENT_TO_DETECTION = True

    # Comment to Quarantine
    COMMENT_TO_QUARANTINE = True