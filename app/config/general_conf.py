"""General connector configuration: logging, runtime mode, time window, and verdicts."""

import pathlib
import logging as log
from enum import Enum
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())


class VERDICT(Enum):
    """VMRay analysis verdict levels."""

    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CLEAN = "clean"


class RUNTIME_MODE(Enum):
    """Execution mode for the connector process."""

    DOCKER = "DOCKER"
    CLI = "CLI"


class GeneralConfig:
    """Top-level runtime configuration shared across all connector modules.

    Attributes:
        LOG_DIR (pathlib.Path): Directory where log files are written.
        LOG_FILE_PATH (pathlib.Path): Full path to the connector log file.
        LOG_LEVEL (int): Python logging level (e.g. ``logging.INFO``).
        SELECTED_VERDICTS (list[str]): Verdict string values that the connector
            will act on (e.g. create IOCs, post comments). Uses the string form
            of :class:`VERDICT` members because the VMRay API returns strings.
        TIME_SPAN (int): Look-back window in seconds used when querying
            CrowdStrike for recent events. Default is 3 hours (10 800 s).
        RUNTIME_MODE (RUNTIME_MODE): Controls whether the connector runs once
            (``CLI``) or loops continuously (``DOCKER``).
    """

    LOG_DIR = pathlib.Path(__file__).parent.parent / "log"
    LOG_FILE_PATH = LOG_DIR / pathlib.Path("cs-connector.log")
    LOG_LEVEL = log.INFO
    SELECTED_VERDICTS = [VERDICT.MALICIOUS.value]
    TIME_SPAN = 1110800
    RUNTIME_MODE = RUNTIME_MODE.DOCKER
