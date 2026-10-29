# Historical digest retained for the quarantine-record exercise; the pickle
# bytes and their builder are no longer present in the application repository.
QUARANTINED_ARTIFACT_SHA256 = "22e1a204f515884ef978482e768a3022b7681a9813e109c84f7862fec5971b66"
POISONED_ARTIFACT_SHA256 = QUARANTINED_ARTIFACT_SHA256  # legacy answer name
VULNERABLE_PACKAGE = "pyyaml==5.3.1"  # CVE-2020-14343


def normalize_hash(value: str) -> str:
    return value.strip().lower().removeprefix("sha256:")


def normalize_package(value: str) -> str:
    # keep the version pin; normalize only whitespace/case and underscores
    return value.strip().lower().replace("_", "-")
