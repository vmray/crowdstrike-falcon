from config.general_conf import VERDICT


class Sample:
    """
    Sample Class to track a single file hash through the connector pipeline.
    All state is stored as instance variables to avoid shared mutable defaults.
    """

    def __init__(self, sample_sha256: str, vmray_result: dict = None) -> None:
        self.sample_sha256: str = sample_sha256
        self.zipped_path: str = ""
        self.unzipped_path: str = ""
        self.downloaded_successfully: bool = False
        # VMRay variables
        self.vmray_metadata: dict = {}
        self.vmray_result: dict = vmray_result if vmray_result is not None else {}
        self.vmray_submit_successfully: bool = False
        self.vmray_submission_finished: bool = False
        self.vmray_verdict: VERDICT = VERDICT.SUSPICIOUS
        self.vmray_submission_id: str = ""
        self.vmray_sample_id: str = ""

    def __str__(self) -> str:
        return (
            f"{self.sample_sha256} -- {self.zipped_path} -- "
            f"{self.unzipped_path} -- {self.vmray_metadata} -- {self.vmray_result}"
        )

