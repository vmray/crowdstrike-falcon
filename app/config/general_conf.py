import pathlib
import logging as log
from enum import Enum

# VMRay verdicts


class VERDICT(Enum):
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CLEAN = "clean"
    
# Runtime mode of connector
class RUNTIME_MODE(Enum):
    DOCKER = "DOCKER"
    CLI = "CLI"


# General Configuration
class GeneralConfig:
    # Log directory
    LOG_DIR = pathlib.Path("log")

    # Log file path
    LOG_FILE_PATH = LOG_DIR / pathlib.Path("cs-connector.log")

    # Log verbosity level
    LOG_LEVEL = log.DEBUG

    # Selected verdicts's values (!!!Because VMray report has a string value!!!) to process and report back to CrowdStrike
    SELECTED_VERDICTS = [VERDICT.MALICIOUS.value]

    # Time span between script iterations (seconds) default: 3 hours
    TIME_SPAN = 10800

    # Runtime mode for script
    # If selected as CLI, script works only once, you need to create cron job for continuos processing
    # If selected as DOCKER, scripts works continuously with TIME_SPAN above
    RUNTIME_MODE = RUNTIME_MODE.DOCKER
    
    # Open case if sample cannot be submitted to VMRay or downloaded from CrowdStrike
    SUBMIT_OR_DOWNLOAD_ERROR_OPEN_CASE = False
