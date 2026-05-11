# User Guide — CrowdStrike Falcon Connector for VMRay

This guide walks through everything needed to set up and operate the connector from scratch, including both CLI and Docker deployment modes.

---

## Prerequisites

Before you begin, confirm that you have:

- **Python 3.10 or newer** installed (CLI deployment only).
- **Docker** installed (Docker deployment only).
- A **CrowdStrike Falcon Insight XDR** tenant with API access.
- A **VMRay Analyzer** account (cloud or on-premises) with a REST API key.
- Network access from the machine running the connector to both the CrowdStrike API (`api.us-2.crowdstrike.com` or your regional endpoint) and your VMRay instance.

---

## Step 1: Obtain Credentials

### CrowdStrike API Client

1. Log in to the Falcon console.
2. Navigate to **Support and Resources → API Clients and Keys**.
3. Click **Add new API client** and assign the following scopes:

   | Scope | Read | Write |
   |---|:---:|:---:|
   | Alerts | ✓ | ✓ |
   | Detections | ✓ | ✓ |
   | IOC Management | ✓ | ✓ |
   | IOCs (Indicators of Compromise) | ✓ | ✓ |
   | Quarantined Files | ✓ | ✓ |
   | Sample Uploads | ✓ | ✓ |

4. Save the generated **Client ID** and **Client Secret**.

> **Region note:** The default base URL targets the US-2 region (`https://api.us-2.crowdstrike.com`). If your tenant is in a different region, set `CROWDSTRIKE_BASE_URL` in `.env` to the correct endpoint (e.g. `https://api.eu-1.crowdstrike.com`).

### VMRay API Key

1. Log in to the VMRay web interface.
2. Navigate to **Analysis Settings → API Keys**.
3. Create a new key with **Report** access (or **Verdict** if you only need verdict data).
4. Copy the generated API key.

---

## Step 2: Install and Configure

### Clone and install

```bash
git clone <repository-url>
cd crowdstrike-falcon-connector
pip install -r app/requirements.txt
```

### Set up credentials

```bash
# Linux / macOS
cp .env.example .env

# Windows (CMD)
copy .env.example .env
```

Edit `.env`:

```env
CROWDSTRIKE_CLIENT_ID=abc123...
CROWDSTRIKE_CLIENT_SECRET=xyz789...
CROWDSTRIKE_BASE_URL=                  # leave blank for us-2 default
VMRAY_API_KEY=your-vmray-key
VMRAY_BASE_URL=                             # leave blank for eu.cloud.vmray.com default
```

Credentials are never stored in source files — the connector reads them from environment variables at startup.

### Tune the configuration files

All three config files live in `app/config/`. Edit only the fields relevant to your deployment.

#### `app/config/general_conf.py`

```python
class GeneralConfig:
    LOG_LEVEL = log.INFO            # Change to log.DEBUG for verbose output
    SELECTED_VERDICTS = [VERDICT.MALICIOUS.value]   # Add VERDICT.SUSPICIOUS.value to also act on suspicious
    TIME_SPAN = 10800               # Look-back window in seconds (3 hours)
    RUNTIME_MODE = RUNTIME_MODE.CLI # Change to RUNTIME_MODE.DOCKER for continuous loop
```

#### `app/config/crowdstrike_conf.py`

```python
class CrowdStrikeConfig:
    SELECTED_DATA_SOURCES = [DATA_SOURCE.ALERT, DATA_SOURCE.QUARANTINE]
    COMMENT_TO_DETECTION = True     # Set False to disable alert comments
    COMMENT_TO_QUARANTINE = True    # Set False to disable quarantine comments/actions
```

To poll only alerts (no quarantines), change `SELECTED_DATA_SOURCES` to `[DATA_SOURCE.ALERT]`.

#### `app/config/vmray_conf.py`

```python
class VMRayConfig:
    API_KEY_TYPE = "report"         # "report" or "verdict"
    SSL_VERIFY = False              # Set True to enforce TLS certificate verification
    ANALYSIS_TIMEOUT = 120          # Sandbox analysis timeout (seconds)
    ANALYSIS_JOB_TIMEOUT = 3600      # Max wait for VMRay to finish (seconds)
    POLL_INTERVAL = ANALYSIS_JOB_TIMEOUT // 100  # Polling interval (seconds)
    RESUBMIT = True                 # Re-analyse samples already in VMRay
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]
```

---

## Step 3: Run the Connector

### CLI mode

The connector must be launched from the `app/` directory so that the `config/` and `lib/` modules resolve correctly. Set `RUNTIME_MODE = RUNTIME_MODE.CLI` in `general_conf.py`.

```bash
cd app
python connector.py
```

The connector will:
1. Authenticate with CrowdStrike and VMRay.
2. Fetch alerts and quarantines from the last `TIME_SPAN` seconds.
3. Check each unique SHA-256 hash against VMRay.
4. Download, submit, and wait for any new samples.
5. Write comments, create IOCs, and update quarantine dispositions.
6. Clean up downloaded files.
7. Exit.

### Docker mode

Set `RUNTIME_MODE = RUNTIME_MODE.DOCKER` in `general_conf.py`, then:

```bash
docker build -t cs_connector .
```

```bash
# Linux / macOS
docker run -d \
  -v $(pwd)/app/log:/app/log \
  --env-file .env \
  --name cs_connector \
  cs_connector

# Windows (PowerShell)
docker run -d `
  -v ${PWD}/app/log:/app/log `
  --env-file .env `
  --name cs_connector `
  cs_connector

# Windows (CMD)
docker run -d -v %cd%/app/log:/app/log --env-file .env --name cs_connector cs_connector
```

In Docker mode the connector loops indefinitely, sleeping `TIME_SPAN` seconds between runs. The container:
- Runs as a non-root `connector` user.
- Creates `/app/log` and `/app/downloads` automatically on startup.
- Writes all logs to `/app/log/cs-connector.log`.

To follow logs in real time:

```bash
docker logs -f cs_connector
```

---

## Step 4: Verify the Connector Is Working

After the first run, check the log file:

```bash
# Linux / macOS
tail -f app/log/cs-connector.log

# Windows (PowerShell)
Get-Content -Wait app/log/cs-connector.log
```

A successful run produces lines similar to:

```
INFO  VMRay Connector for CrowdStrike Falcon starting
INFO  CrowdStrike Alerts API authenticated
INFO  CrowdStrike Quarantine API authenticated
INFO  CrowdStrike SampleUploads API authenticated
INFO  CrowdStrike IOC API authenticated
INFO  VMRay API authenticated (report key)
INFO  VMRay health check succeeded.
INFO  Quarantines: retrieved 3 item(s), 2 unique hash(es)
INFO  Detections: retrieved 5 alert(s), 4 unique hash(es)
INFO  Number of samples to process: 5
INFO  Sample <sha256> found in VMRay (verdict=malicious) — no resubmission
INFO  2 sample(s) to download and submit to VMRay
INFO  Sample <sha256> downloaded and verified successfully
INFO  Sample <sha256> submitted to VMRay (submission_id=12345)
INFO  Submission 12345 finished for sample <sha256>
INFO  Posted comment(s) to 2 detection(s) for <sha256>
INFO  IOC creation completed for <sha256>
INFO  Posted comment to quarantine for <sha256>
INFO  Files cleanup completed.
INFO  VMRay connector run completed.
```

In CrowdStrike, navigate to an alert that was processed — it should have a comment beginning with `[VMRay] Verdict: Malicious` attached to it.

---

## Typical Usage Scenarios

### Scenario 1: Triage an outbreak

You receive a notification that several endpoints have been quarantined. Set `TIME_SPAN` to cover the outbreak window (e.g. `86400` for 24 hours) and run the connector once in CLI mode. It will batch-submit all quarantined hashes and write verdicts back.

### Scenario 2: Continuous monitoring

Deploy the connector in Docker mode with `TIME_SPAN = 3600` (1 hour). Every hour it sweeps for new alerts and quarantines, submits unanalysed samples, and keeps IOCs up to date automatically.

### Scenario 3: Suspicious-only resubmission

You want to leave malicious verdicts in place but re-analyse anything that came back suspicious last time. Set:

```python
RESUBMIT = True
RESUBMISSION_VERDICTS = [VERDICT.SUSPICIOUS]
```

The connector will re-submit only suspicious samples on each run.

---

## Understanding the Results

### Alert comments

When `COMMENT_TO_DETECTION = True`, the connector appends one or more structured comments to each matched alert. Comments are capped at 1024 characters; if the full result overflows, it is split into multiple sequential comment posts. A typical comment looks like:

```
[VMRay] Verdict: Malicious | Analysis: https://eu.cloud.vmray.com/...
Threat Names: Trojan.GenericKD.12345
Classifications: Trojan

VTIs (Category | Operation | Score):
Persistence | Modifies autorun registry keys | 5
Network | Connects to known C2 domain | 5
```

### IOC indicators

For every malicious verdict the connector creates:

- A **sha256** IOC (action: `prevent`) for the sample hash.
- Additional **sha256** IOCs for any malicious file hashes found during analysis (Ransomware-classified files are excluded).
- **ipv4** IOCs (action: `detect`) for contacted IP addresses.
- **domain** IOCs (action: `detect`) for contacted domains.

All IOCs are tagged `VMRAY`, applied globally, and cover `mac`, `windows`, and `linux` platforms.

### Quarantine disposition

After analysis, each matched quarantine item is updated:

| Verdict | Disposition |
|---|---|
| Malicious | `unrelease` — keeps the file quarantined |
| Suspicious | `unrelease` — keeps the file quarantined |
| Clean | `release` — releases the file from quarantine |

---

## Stopping and Restarting

**Docker:**

```bash
docker stop cs_connector
docker start cs_connector
```
