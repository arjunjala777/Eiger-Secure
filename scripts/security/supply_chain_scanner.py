"""Fail-closed artifact admission. Inspection never executes serialized code."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from halcyon.scan_artifact import scan

MAX_SIZE = 256 * 1024 * 1024


def scan_artifacts(directory="artifacts", approved_hashes=None):
    base = Path(directory)
    results = []
    for path in sorted(base.rglob("*")) if base.is_dir() else []:
        if not path.is_file():
            continue
        status = "UNKNOWN"
        reason = "No approved artifact digest"
        digest = ""
        if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
            reason = "Symbolic links not admitted"
        elif path.stat().st_size > MAX_SIZE:
            reason = "Artifact exceeds bounded inspection budget"
        else:
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if path.suffix.lower() in (".pkl", ".pickle", ".pt", ".bin"):
                inspected = scan(path)
                status = "MALICIOUS" if inspected["malicious"] else "UNKNOWN"
                reason = "Executable/unsupported serialization is not an admitted model format"
            elif digest in (approved_hashes or set()):
                try:
                    if path.suffix.lower() == ".json":
                        json.loads(data)
                    elif path.suffix.lower() == ".safetensors":
                        if len(data) < 8:
                            raise ValueError("Missing header")
                        length = int.from_bytes(data[:8], "little")
                        if length > 8 * 1024 * 1024 or 8 + length > len(data):
                            raise ValueError("Invalid header size")
                        header = json.loads(data[8 : 8 + length])
                        payload_size = len(data) - 8 - length
                        if not isinstance(header, dict):
                            raise ValueError("Invalid header")
                        for key, tensor in header.items():
                            if key == "__metadata__":
                                continue
                            start, end = tensor["data_offsets"]
                            if (
                                type(start) is not int
                                or type(end) is not int
                                or not 0 <= start <= end <= payload_size
                            ):
                                raise ValueError("Invalid tensor bounds")
                    else:
                        raise ValueError("Unsupported admitted format")
                    status = "APPROVED"
                    reason = "Approved digest and supported format validated"
                except (ValueError, TypeError, KeyError, UnicodeError):
                    status = "UNKNOWN"
                    reason = "Malformed or unsupported artifact"
        results.append(
            {
                "file": str(path.relative_to(base)),
                "sha256": digest,
                "status": status,
                "reason": reason,
            }
        )
    return {
        "scanner": "Eiger artifact admission",
        "scanned_count": len(results),
        "admission_verdict": "PASS"
        if results and all(r["status"] == "APPROVED" for r in results)
        else "FAIL",
        "results": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", default="artifacts")
    parser.add_argument("--approved-manifest")
    parser.add_argument("--output", default="reports/supply_chain_scan.json")
    args = parser.parse_args()
    approved = (
        set(json.loads(Path(args.approved_manifest).read_text()))
        if args.approved_manifest
        else set()
    )
    report = scan_artifacts(args.directory, approved)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))
    print(report["admission_verdict"])
    raise SystemExit(0 if report["admission_verdict"] == "PASS" else 1)
