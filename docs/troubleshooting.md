# Troubleshooting Guide — CrowdStrike Falcon Connector for VMRay

---

## How to Read the Logs

All connector activity is written to `app/log/cs-connector.log`. Each line follows this format:

```
<timestamp> [PID <pid>] <module>:<line> <LEVEL> <message>
```

To tail live output:

```bash
# Linux / macOS
tail -f app/log/cs-connector.log

# Windows (PowerShell)
Get-Content -Wait app/log/cs-connector.log
```

For Docker:

```bash
docker logs -f cs_connector
```

Increase verbosity by setting `LOG_LEVEL = log.DEBUG` in `general_conf.py` — this adds per-sample download/submission steps, VMRay API call traces, and IOC lookup details.

---

## Authentication Failures

### CrowdStrike API authentication failed

**Symptom:** Log line:
```
ERROR CrowdStrike Alerts API authentication failed — check client ID/secret and permissions
```
followed by connector exit.

**Causes and fixes:**

| Cause | Fix |
|---|---|
| `CROWDSTRIKE_CLIENT_ID` or `CROWDSTRIKE_CLIENT_SECRET` is blank or wrong | Check `.env` — both values must be non-empty. |
| `.env` file is not in the project root or not being loaded | The connector calls `load_dotenv(find_dotenv())` at startup. Confirm `.env` exists alongside `.env.example`. |
| API client does not have the required permission scopes | In the Falcon console, verify the client has Read+Write on Alerts, Detections, IOC Management, IOCs, Quarantined Files, and Sample Uploads. |
| Wrong regional base URL | Set `CROWDSTRIKE_BASE_URL` in `.env` to match your tenant's region (e.g. `https://api.eu-1.crowdstrike.com`). |
| API client has been revoked or expired | Generate a new API client in the Falcon console and update `.env`. |

### VMRay authentication or health check failed

**Symptom:** Log line:
```
ERROR VMRay authentication failed: ...
ERROR VMRay health check failed: ...
```

**Causes and fixes:**

| Cause | Fix |
|---|---|
| `VMRAY_API_KEY` is blank or wrong | Check `.env`. |
| Wrong `VMRAY_BASE_URL` | Confirm the URL points to your VMRay instance. Cloud default: `https://eu.cloud.vmray.com`. |
| TLS certificate error (self-signed cert) | `SSL_VERIFY` defaults to `False` — certificate verification is disabled by default. Set `SSL_VERIFY = True` in `vmray_conf.py` to enforce verification in production environments. |
| Firewall or proxy blocking outbound HTTPS | Ensure the host can reach the VMRay endpoint on port 443. |

---

## No Hashes Found / Nothing to Process

**Symptom:** Log line:
```
WARNING No hashes found across configured data sources (Alert, Quarantine) — nothing to process
```

**Causes and fixes:**

| Cause | Fix |
|---|---|
| `TIME_SPAN` is too short — no events in that window | Increase `TIME_SPAN` (e.g. `86400` for 24 hours) for a one-off catch-up run. |
| `SELECTED_DATA_SOURCES` is empty or misconfigured | Confirm `crowdstrike_conf.py` includes `DATA_SOURCE.ALERT` and/or `DATA_SOURCE.QUARANTINE`. |
| No actual alerts or quarantines exist in the tenant | Verify in the Falcon console — the connector can only process events that exist. |

---

## Sample Download Failures

**Symptom:** Log lines:
```
WARNING Download failed for <sha256>: ...
WARNING Skipping actions for <sha256>: download failed
```

**Causes and fixes:**

| Cause | Fix |
|---|---|
| Sample not in SampleUploads (file was never uploaded) | Some detections reference hashes of files that were never uploaded to CrowdStrike — no action required. |
| `DOWNLOAD_DIR_PATH` does not exist or is not writable | The connector creates `app/downloads/` on startup. Check filesystem permissions if running as a restricted user. |
| Network timeout downloading a large sample | The FalconPy SDK uses the default `requests` timeout. If downloads consistently fail for large files, consider increasing the SDK timeout. |
| SHA-256 integrity check fails after extraction | The downloaded file is corrupted. The connector logs an integrity failure and marks the sample as not downloaded. Retry on the next run. |

---

## VMRay Submission Failures

**Symptom:** Log lines:
```
ERROR Failed to submit sample <sha256> to VMRay: ...
WARNING Skipping actions for <sha256>: VMRay submission failed
```

**Causes and fixes:**

| Cause | Fix |
|---|---|
| API key has insufficient permissions (verdict key used instead of report key) | Use a **Report** API key for full IOC and VTI access. Set `API_KEY_TYPE = "report"` in `vmray_conf.py`. |
| Submission quota exceeded on VMRay | Check your VMRay account's submission limits. |
| File type not supported by VMRay | VMRay rejects certain file types. Check the VMRay documentation for supported formats. |
| `sample_file` is missing or unzipped path is wrong | Ensure `download_malware_sample` completed successfully before submission. |

---

## VMRay Analysis Timeout

**Symptom:** Log line:
```
WARNING Submission <id> exceeded the configured timeout (3600s)
WARNING Skipping actions for <sha256>: VMRay analysis timed out
```

**Causes:**
- The sample requires more sandbox time than `ANALYSIS_JOB_TIMEOUT` allows.
- The VMRay instance is under heavy load.

**Fixes:**
- Increase `ANALYSIS_JOB_TIMEOUT` in `vmray_conf.py` (e.g. `1200` for 20 minutes).
- Increase `ANALYSIS_TIMEOUT` (the per-sandbox timeout sent to VMRay) if the sample is a complex document or installer.
- In Docker mode, timed-out samples are retried on the next connector run if they complete in VMRay before then (they will be found in the database lookup).

---

## IOC Creation Failures

**Symptom:** Log line:
```
ERROR Failed to create sha256 IOC <value>: ...
```

**Causes and fixes:**

| Cause | Fix |
|---|---|
| IOC already exists (duplicate) | The connector calls `check_ioc()` before creating — if the duplicate check itself fails (API error), creation may be attempted and rejected. Check the API error message in the log. |
| API client missing `IOC Management` write permission | Add the scope in the Falcon console. |
| Invalid IOC value (e.g. malformed IP or domain from VMRay) | The connector does not sanitise IOC values beyond URL parsing. If a VMRay IOC contains an unexpected format, it may be rejected. Check the debug log for the raw value. |

---

## Comments Not Appearing on Alerts or Quarantines

**Symptom:** Analysis completed, IOCs created, but no comments visible in Falcon.

**Causes and fixes:**

| Cause | Fix |
|---|---|
| `COMMENT_TO_DETECTION = False` | Set to `True` in `crowdstrike_conf.py`. |
| `COMMENT_TO_QUARANTINE = False` | Set to `True` in `crowdstrike_conf.py`. |
| Alert's `composite_id` or quarantine's `quarantine_id` is empty | Logged at DEBUG level. Enable debug logging to inspect the DTOs. |
| Alert API `update_alerts_v3` returned non-200 | Check the log for the error message — usually a permissions issue. |
| Verdict not in `SELECTED_VERDICTS` | If the verdict is `suspicious` but `SELECTED_VERDICTS` only contains `"malicious"`, comments are still posted for all finished samples. However, IOC creation is gated on `MALICIOUS` verdict only. |

---

## Duplicate Processing

**Symptom:** The same sample is submitted to VMRay on every run.

**Cause:** `RESUBMIT = True` with the sample's verdict in `RESUBMISSION_VERDICTS`.

**Fix:** If you do not want repeated resubmission, either:
- Set `RESUBMIT = False` to never resubmit.
- Or narrow `RESUBMISSION_VERDICTS` — remove the verdict that keeps triggering it.

---

## Docker-Specific Issues

### Container exits immediately

Check that the entrypoint can execute:

```bash
docker logs cs_connector
```

Common causes:
- `RUNTIME_MODE` is set to `CLI` — the container runs once and exits. Change to `RUNTIME_MODE.DOCKER` for continuous operation.
- An unhandled exception during startup (authentication failure, missing env var).

### Log directory is empty on the host

Ensure you mount the correct path:

```bash
docker run -d -v $(pwd)/app/log:/app/log --env-file .env cs_connector
```

The connector writes logs to `/app/log/cs-connector.log` inside the container.

### Permission denied on `/app/downloads` or `/app/log`

The `docker-entrypoint.sh` script creates these directories and assigns them to the `connector` user. If you mount an external volume with root ownership, the non-root `connector` user cannot write to it. Fix by pre-creating the directory with world-writable permissions or setting appropriate ownership:

```bash
# Linux / macOS
mkdir -p app/log
chmod 777 app/log

# Windows (PowerShell)
New-Item -ItemType Directory -Force app/log
```

---

## Performance and Scaling

### Connector takes too long per run

- `ANALYSIS_JOB_TIMEOUT` is the dominant factor — each run blocks until all submitted samples finish.
- If you have many new samples, consider running in Docker mode so the connector can process them continuously rather than waiting for all submissions in a single CLI run.
- Large `TIME_SPAN` values cause more events to be fetched per run. Reduce the window if you're running frequently.

### Too many API calls to CrowdStrike

The connector paginates through all results within the time window. With a very large `TIME_SPAN` and high event volume, this generates many API calls. The CrowdStrike FalconPy SDK handles rate limiting transparently, but reducing `TIME_SPAN` lowers the per-run query volume.
