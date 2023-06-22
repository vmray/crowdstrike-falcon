from config.general_conf import VERDICT

class Sample:
    """
      Sample Class to keep file object
    """
    sample_sha256: str = ""
    zipped_path: str = ""
    unzipped_path: str = ""
    downloaded_successfully: bool = False
    # Vmray variables
    vmray_metadata: dict = {}
    vmray_result: dict = {}
    vmray_submit_successfully: bool = False
    vmray_verdict: VERDICT = VERDICT.SUSPICIOUS
    vmray_submission_id: str = ""
    vmray_sample_id: str = ""
    vmray_analysis_completed: bool = False
    

    def __init__(self, sample_sha256, vmray_result=None):
        self.sample_sha256 = sample_sha256
        self.vmray_result = vmray_result

    def __str__(self) -> str:
        return f"{self.sample_sha256} -- {self.zipped_path} -- {self.unzipped_path} -- {self.vmray_metadata} -- {self.vmray_result}"
    
