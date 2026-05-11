# CrowdStrike Falcon Connector for VMRay 

**Latest Version:** 2.0 - **Release Date:** 11/05/2026

## Overview

This project integrates CrowdStrike Falcon Insight XDR and VMRay FinalVerdict / TotalInsight. It equips customers with extra intel regarding the threats detected by CrowdStrike Falcon Insight XDR on their endpoints. Depending on the configuration, the Connector collects unique SHA256 hash values from:

- Detections
- Quarantines

It then downloads and submits respective samples into the VMRay Analyzer for detonation and deep dynamic analysis. After the submission, it retrieves the verdict and IOC values from VMRay and updates Detection and Quarantine Objects, and creates IOCs.

## Related VMRay Products
The connector supports the following VMRay products:

- Final Verdict
- Total Insight

## Project Structure

    app                             # Main project directory
    ├─── config                     # Configuration directory
    │   └─── __init__.py
    │   └─── constants.py           # Shared constants (IOC tags, actions, limits)
    │   └─── crowdstrike_conf.py    # CrowdStrike configuration file
    │   └─── general_conf.py        # General configuration file
    │   └─── vmray_conf.py          # VMRay configuration file
    ├─── downloads                  # Directory for extracted binaries
    ├─── lib                        # Library directory
    │   └─── __init__.py
    │   └─── CrowdStrike.py         # CrowdStrike API functions
    │   └─── VMRay.py               # VMRay API functions
    │   └─── Sample.py              # Sample class for tracking samples through the pipeline
    ├─── log                        # Log directory for connector
    │   └─── cs-connector.log       # Log file for connector
    └─── __init__.py
    └─── connector.py               # Main connector application
    └─── requirements.txt           # Python library requirements
    .env.example                    # Example environment variable file
    Dockerfile                      # Docker build file
    docker-entrypoint.sh            # Docker container entrypoint script


## Requirements
- Python >3.10 with required packages ([Required Packages](app/requirements.txt))
- CrowdStrike Falcon Insight XDR
- VMRay Analyzer
- Docker (optional)

## Installation

Clone the repository into a local folder.

    git clone https://github.com/vmray/crowdstrike-falcon.git

Install the requirements.

    pip install -r app/requirements.txt

Copy `.env.example` to `.env` and populate your credentials:

    cp .env.example .env

Edit the [vmray_conf.py](app/config/vmray_conf.py), [general_conf.py](app/config/general_conf.py), and [crowdstrike_conf.py](app/config/crowdstrike_conf.py) files and update with your configurations.

## Configuration

### CrowdStrike Falcon Insight XDR

- Create a Custom Access Level with the permissions below with a web interface for API at Create API section. (`Support and Resources > API client and keys`)

|       Scope       |    Read   |       Write       	 |
|:---------------------|:--------------------:|:-----------------------:|
| Alerts               | :ballot_box_with_check: | :ballot_box_with_check: |
| Detections    | :ballot_box_with_check: | :ballot_box_with_check: |
|  IOC Management  | :ballot_box_with_check: | :ballot_box_with_check: |
|  IOCs (Indicators of Compromise) | :ballot_box_with_check: | :ballot_box_with_check: |
|  Quarantined Files  | :ballot_box_with_check: | :ballot_box_with_check: |
| Sample uploads | :ballot_box_with_check: | :ballot_box_with_check: |

## Configuration for CrowdStrike
- Edit the `CrowdStrikeConfig` class in [crowdstrike_conf.py](app/config/crowdstrike_conf.py) file

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `CLIENT_ID`       | Client ID (set via `CROWDSTRIKE_CLIENT_ID` env var) | None |
| `CLIENT_SECRET`   | Client Secret (set via `CROWDSTRIKE_CLIENT_SECRET` env var) | None |
| `BASE_URL`           | CrowdStrike Cloud base URL (override via `CROWDSTRIKE_BASE_URL` env var) | `https://api.us-2.crowdstrike.com` |
| `DOWNLOAD_DIR`        | Directory path for sample downloads | `downloads` |
| `SELECTED_DATA_SOURCES` | Selected CrowdStrike data source  | [`DATA_SOURCE.ALERT`, `DATA_SOURCE.QUARANTINE`] |
| `COMMENT_TO_DETECTION` | Update Detection with a comment [`True`/`False`]  | `True` |
| `COMMENT_TO_QUARANTINE` | Update Quarantine with a comment [`True`/`False`]  | `True` |

## Configuration for VMRay

- Create API Key with web interface. (`Analysis Settings > API Keys`)

- Edit the `VMRayConfig` class in [vmray_conf.py](app/config/vmray_conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `API_KEY_TYPE`| VMRay API Key Type [`report`/`verdict`] | `report` |
| `API_KEY`| API Key (set via `VMRAY_API_KEY` env var) |  |
| `URL`| URL of VMRay instance (override via `VMRAY_BASE_URL` env var) | `https://eu.cloud.vmray.com` |
| `CONNECTOR_NAME`| User Agent string for VMRay API requests | `CrowdStrikeCloudConnector` |
| `SSL_VERIFY`| Enable or disable certificate verification [`True`/`False`] | `True` |
| `SUBMISSION_COMMENT`| Comment for submitted samples | `Sample from VMRay CrowdStrike Connector` |
| `SUBMISSION_TAGS`| Tags for submitted samples (no spaces allowed) | `["CrowdStrike"]` |
| `ANALYSIS_TIMEOUT`| Timeout for individual submission analyses in seconds | `120` |
| `ANALYSIS_JOB_TIMEOUT`| Maximum total wait time for submission completion in seconds | `3600` |
| `POLL_INTERVAL`| Seconds between polling rounds while waiting for analysis | `ANALYSIS_JOB_TIMEOUT // 100` |
| `RESUBMIT`| Re-analyze samples already seen by VMRay [`True`/`False`] | `True` |
| `RESUBMISSION_VERDICTS`| Verdicts that trigger resubmission | `[VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]` |

## General Connector Configurations

- Edit the `GeneralConfig` class in [general_conf.py](app/config/general_conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `LOG_FILE_PATH`| Connector log file path | `app/log/cs-connector.log` |
| `LOG_LEVEL`| Logging verbosity level | `INFO` |
| `SELECTED_VERDICTS`| Verdicts to process and report back to CrowdStrike | `["malicious"]` |
| `TIME_SPAN`| Time span between script iterations in seconds | `10800` |
| `RUNTIME_MODE`| Runtime mode for script [`CLI`/`DOCKER`] | `DOCKER` |

# Running the Connector

## Running with CLI

You can start the connector with the command line after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.CLI` in the `GeneralConfig`. Also, you can create a cron job for continuous processing.

The connector must be run from the `app/` directory:

    cd app
    python connector.py

## Running with Docker

You can create and start a Docker image with Dockerfile after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.DOCKER` in the `GeneralConfig`.

    docker build -t cs_connector .
    docker run -d -v $(pwd)/app/log:/app/log --env-file .env -t cs_connector

After running the Docker container, you can see connector logs in the log directory on your host machine.
