import hashlib
import json
from pathlib import Path

from halcyon.config import Settings


class ArtifactError(Exception):
    """Raised by the hardened loader when an artifact is refused."""


# Pinned sha256 allowlist of trusted safetensors artifacts (empty seed; ops adds hashes).
ALLOWED_HASHES: set[str] = set()


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_artifact(path: str | Path, settings: Settings) -> object:
    p = Path(path)
    if p.suffix.lower() in {".pkl", ".pickle"}:
        raise ArtifactError("refused: pickle deserialization is disabled in every profile")
    if settings.sec_artifact_verification:
        if p.suffix != ".safetensors":
            raise ArtifactError(f"refused: only .safetensors permitted, got '{p.suffix}'")
        digest = sha256_file(p)
        if digest not in ALLOWED_HASHES:
            raise ArtifactError(f"refused: {digest} not in pinned allowlist")
        return p.read_bytes()  # teaching stub: a real reader would parse safetensors
    if p.suffix.lower() == ".json":
        if p.stat().st_size > 1024 * 1024:
            raise ArtifactError("refused: JSON artifact exceeds the 1 MiB limit")
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArtifactError("refused: invalid JSON artifact") from exc
    if p.suffix == ".safetensors":
        return p.read_bytes()
    raise ArtifactError(f"refused: unsupported artifact format '{p.suffix}'")
