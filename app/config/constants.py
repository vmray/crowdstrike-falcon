"""Constants for the connector."""

# ----- CrowdStrike API -----
CS_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CS_PRODUCT_FILTER = 'epp'
CS_ALERTS_PAGE_LIMIT = 100
CS_QUARANTINE_PAGE_LIMIT = 5000
CS_QUARANTINE_BATCH_SIZE = 100
CS_BASE_URL = "https://api.us-2.crowdstrike.com"

# ----- Sample handling -----
SAMPLE_ZIP_PASSWORD = 'infected'
HASH_READ_BUFFER_SIZE = 4096

# ----- IOC creation -----
IOC_TAGS = ['VMRAY']
IOC_PLATFORMS = ['mac', 'windows', 'linux']
IOC_SEVERITY = 'high'
IOC_ACTION_PREVENT = 'prevent'
IOC_ACTION_DETECT = 'detect'

# ----- Quarantine actions -----
QUARANTINE_ACTION_UNRELEASE = 'unrelease'
QUARANTINE_ACTION_RELEASE = 'release'

# ----- Comment formatting -----
MAX_COMMENT_LENGTH = 1024

# ----- VMRay -----
VMRAY_JOB_STATUS_INWORK = 'inwork'
VMRAY_BASE_URL = "https://eu.cloud.vmray.com"
