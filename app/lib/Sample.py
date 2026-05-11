"""Data transfer object representing a single sample through the connector pipeline."""

from config.general_conf import VERDICT


class Sample:
    """Tracks a single file hash through the full connector pipeline.

    Args:
        sample_sha256 (str): SHA-256 hash of the file being processed.
        vmray_result (dict, optional): Pre-populated IOC result dict. Defaults to an
            empty dict so each instance has its own mutable default.

    Attributes:
        sample_sha256 (str): SHA-256 hash of the file.
        zipped_path (str): Filesystem path of the password-protected ZIP downloaded
            from CrowdStrike SampleUploads.
        unzipped_path (str): Filesystem path of the extracted sample file.
        downloaded_successfully (bool): True once the file has been downloaded and
            its integrity has been verified.
        vmray_metadata (dict): Parsed sample summary returned by VMRay
            (e.g. ``sample_id``, ``sample_verdict``, ``sample_webif_url``).
        vmray_result (dict): Parsed IOC data returned by VMRay, keyed by IOC type
            (``sha256``, ``ipv4``, ``domain``, ``cmdline``, etc.).
        vmray_vtis (list): VTIs (VMRay Threat Identifier) entries for the sample.
        vmray_submit_successfully (bool): True once the sample has been accepted by
            the VMRay submission endpoint.
        vmray_submission_finished (bool): True once VMRay analysis has completed
            (or was found in database).
        vmray_verdict (VERDICT): Final verdict assigned by VMRay.
        vmray_submission_id (int | str): VMRay submission ID assigned at submission time.
        vmray_sample_id (int | str): VMRay sample ID for the submitted file.
    """

    def __init__(self, sample_sha256: str, vmray_result: dict = None) -> None:
        self.sample_sha256: str = sample_sha256
        self.zipped_path: str = ""
        self.unzipped_path: str = ""
        self.downloaded_successfully: bool = False
        self.vmray_metadata: dict = {}
        self.vmray_result: dict = vmray_result if vmray_result is not None else {}
        self.vmray_vtis: list = []
        self.vmray_submit_successfully: bool = False
        self.vmray_submission_finished: bool = False
        self.vmray_verdict: VERDICT = VERDICT.SUSPICIOUS
        self.vmray_submission_id: int | str = ""
        self.vmray_sample_id: int | str = ""

    def __str__(self) -> str:
        return (
            f"{self.sample_sha256} -- {self.zipped_path} -- "
            f"{self.unzipped_path} -- {self.vmray_metadata} -- {self.vmray_result}"
        )
