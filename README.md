# VMWare CrowdStrike Connector for VMRay Analyzer 

**Latest Version:** 0.1 - **Release Date:** 22/06/2023

## Overview

This project is an integration between CrowdStrike Cloud and VMRay. It allows to enrich created detections as well as to build an extra line of defence to detects threats. Depending on configuration the Connector collects uniqie SHA256 hash values from:

- Detections
- Quarantines

and then downloads and submits respective samples into the VMRay Analyzer for detonation and deep dynamic analysis. After the submission it retrieves the verdict and IOC values from VMRay and update Detection and Quarantine Objects, create IOC, contain(quarantine) machine if needed.

## Related VMRay Products
The connector supports following VMRay products:

- Final Verdict
- Total Insight

## Project Structure

    app                             # Main project directory
    ├─── config                     # Configuration directory
    │   └─── __init__.py 			
    │   └─── crowdstike_conf.py     # CrowdStrike configuration file
    │   └─── general_conf.py        # General configuration file
    │   └─── crowdstike_conf.py     # VMRay configuration file    
    ├─── downloads                  # Directory for extracted binaries
    ├─── lib                        # Library directory
    │   └─── __init__.py 				
    │   └─── CrowdStrike.py         # Crowdstrike API functions
    │   └─── VMRay.py               # VMRay API functions
    │   └─── Sample.py              # Sample class for controlling the samples
    ├─── log                        # Log directory for connector
        └─── cs-connector.log       # Log file for connector
    └─── __init__.py
    └─── connector.py               # Main connector application
    └─── requirements.txt           # Python library requirements
    └─── log                        # Log directory for Docker volume


## Requirements
- Python >3.10 with required packages ([Required Packages](app/requirements.txt))
- CrowdStrike Cloud
- VMRay Analyzer
- Docker (optional)

## Installation

Clone the repository into a local folder.

    git clone https://github.com/vmray/crowdstrike-falcon.git

Install the requirements.

    pip install -r requirements.txt
    
Edit the [vmray_conf.py](app/config/vmray_conf.py) [general_conf.py](app/config/general_conf.py) [crowdstrike_conf.py](app/config/crowdstrike_conf.py)files and update with your configurations.

## Configuration

### CrowdStrike Cloud Configurations

- Create Custom Access Level with the permissions below with web interface for API at Create API section. (`Support and Resources > API client and keys`)

|       Scope       |    Read   |       Write       	 |
|:---------------------|:--------------------:|:-----------------------:|
| Alerts               | :ballot_box_with_check: | :ballot_box_with_check: |
| Detections    | :ballot_box_with_check: | :ballot_box_with_check: |
| Hosts    | :ballot_box_with_check: | :ballot_box_with_check: |
|  Host groups     | :ballot_box_with_check:   | :ballot_box_with_check: |
|  Incidents  |  :ballot_box_with_check: |  :ballot_box_with_check: |
|  IOC Management  | :ballot_box_with_check: | :ballot_box_with_check: | 
|  IOCs (Indicators of Compromise) | :ballot_box_with_check: | :ballot_box_with_check: | 
|  On-demand scans (ODS)  | :ballot_box_with_check: | :ballot_box_with_check: | 
|  Quarantined Files  | :ballot_box_with_check: | :ballot_box_with_check: | 
| Sample uploads | :ballot_box_with_check: | :ballot_box_with_check: |
|  User management | :ballot_box_with_check: | :ballot_box_with_check: |

## Configuration for CrowdStrike
- Edit the `CrowdStrikeConfig` class in [crowdstrike_conf.py](app/config/crowdstrike_conf.py) file

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `CLIENT_ID`       | Client ID | None |
| `CLIENT_SECRET`   | Client Secret | None | 
| `BASE_URL`           | CrowdStrike Cloud base url | `https://api.us-2.crowdstrike.com`|
| `DOWNLOAD_DIR`        | Directory path for sample downloads | `downloads` |
| `SELECTED_DATA_SOURCES` | Selected CrowdStrike data source  | [`DATA_SOURCE.DETECT`, `DATA_SOURCE.QUARANTINE`] |
| `USER_UUID` |  User UUID for case creation |  |
| `COMMMENT_TO_DETECTION` | Update Detection with a comment [`True`/`False`]  | `True` |
| `COMMENT_TO_QUARANTINE` | Update Quarantine with a comment [`True`/`False`]  | `True` |
| `CONTAIN_HOST` | Contain host machine if a detection or quarantine file affect it [`True`/`False`]  | `False` |
| `CREATE_CASE` | Create a Case if a detection or quarantine files when VMRay verdict hits one of CREATE_CASE_LEVELS | `False` |
| `CREATE_CASE_LEVELS` | Case Creation level list from VMRay verdict | `[`VERDICT.SUSPICIOUS`/`VERDICT.MALICIOUS`]` |
| `CASE_USERS` | User uuid that connector can open case RECOMMANDATION: Create a user for connector and follow the cases |  |
| `FIND_ANOTHER_HOST` | Find another host with same IOC | `False` |
| `FIND_ANOTHER_HOST_LEVELS` | Find another host with a IOC. level list from VMRay verdict | `[`VERDICT.SUSPICIOUS`/`VERDICT.MALICIOUS`]` |
| `ADD_THREAT_CLASSIFICATION` | Add comment to Detection with found threat's classification | `True` |
| `ADD_THREAT_NAME` | Add comment to Detection with found threat's name | `True` |

## Configuration for VMRay

- Create API Key with web interface. (`Analysis Settings > API Keys`)

- Edit the `VMRayConfig` class in [vmray_conf.py](app/config/vmray_conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `API_KEY_TYPE`| Enum for VMRay API Key Type [`REPORT`/`VERDICT`] | `REPORT` |
| `API_KEY`| API Key |  |
| `URL`| URL of VMRay instance | `https://eu.cloud.vmray.com` |
|`ConnectorName`| User Agent string for VMRay Api requests | `CrowdStrikeCloudConnector` |
| `SSL_VERIFY`| Enable or disable certificate verification [`True`/`False`] | `True` |
| `SUBMISSION_COMMENT`| Comment for submitted samples | `Sample from VMRay CarbonBlack Connector` |
| `SUBMISSION_TAGS`| Tags for submitted samples | `CrowdStrike` |
| `ANALYSIS_TIMEOUT`| Timeout for submission analyses as seconds | `120` |
| `ANALYSIS_JOB_TIMEOUT`| Max job count for submissions | `600` |
| `DEFAULT_ANALYZER_MODE`| Analyzer mode for normal samples | `reputation_static_dynamic` |
| `RESUBMIT`| Resubmission status which has been already analyzed by VMRay [`True`/`False`] | `False` |
| `RESUBMISSION_VERDICTS`| Selected verdicts to resubmit evidences | `[malicious, suspicious]` |

## General Connector Configurations

- Edit the `GeneralConfig` class in [general_conf.py](app/config/general_conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `LOG_FILE_PATH`| Connector log file path | `cs-connector.log` |
| `LOG LEVEL`| Logging verbosity level | `DEBUG` |
| `SELECTED_VERDICTS`| Selected verdicts to process and report back to CrowdStrike Cloud | `malicious` |
| `TIME_SPAN`| Time span between script iterations as seconds | `10800`|
| `RUNTIME_MODE`| Runtime mode for script | `DOCKER` |

# Running the Connector

## Running with CLI

You can start connector with command line after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.CLI` in the `GeneralConfig`. Also you can create cron job for continuous processing.
    
    python connector.py

## Running with Docker

You can create and start Docker image with Dockerfile after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.DOCKER` in the `GeneralConfig`.

    docker build -t cs_connector .
    docker run -d -v $(pwd)/log:/app/log -t cs_connector

After running the Docker container you can see connector logs in the log directory on your host machine.
