from enum import Enum
import pathlib
from token import COMMENT
from config.general_conf import GeneralConfig, VERDICT

# CrowdStrike DataSource


class DATA_SOURCE(Enum):
    QUARANTINE = "Quarantine"
    DETECT = "Detect"

class CrowdStrikeConfig():
    # CrowdStrike Client ID
    CLIENT_ID = "<CrowdStrike-Client-ID>"


    # CrowdStrike Client Secret
    CLIENT_SECRET = "<CrowdStrike-Client-Secret>"


    # CrowdStrike API Base URL #Default : https://api.us-2.crowdstrike.com
    BASE_URL = 'https://api.us-2.crowdstrike.com'

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
    # User uuid that connector can open case
    USER_UUID = '<EXAMPLE_USER_UUID>' 
    
    # Comment to detection
    COMMMENT_TO_DETECTION = True
    
    # Comment to Quarantine
    COMMENT_TO_QUARANTINE = True
    
    # Contain host machine if a detection or quarantine file affect it
    CONTAIN_HOST = False

    # Contain host level from VMRay verdict
    CONTAIN_HOST_LEVELS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]
    
    # Create a Case if a detection or quarantine files when VMRay verdict hits one of CREATE_CASE_LEVELS
    CREATE_CASE = False
    
    # Case Creation level list from VMRay verdict
    CREATE_CASE_LEVELS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]
    
    # User uuid that connector can open case RECOMMENDED: Create a user for connector and follow the cases
    CASE_USERS = '<EXAMPLE_USER_UUID>'
    
    # Find another host with same IOC
    FIND_ANOTHER_HOST = False 
    
    # Find another host event level list from VMRay verdict
    FIND_ANOTHER_HOST_LEVELS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]
    
    # Add Threat classification to detection object as comment
    ADD_THREAT_CLASSIFICATION = True
    
    # Add threat name to detection object as comment
    ADD_THREAT_NAME = True