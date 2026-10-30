#!/usr/bin/env python3
"""End-to-end regression for bounded trace sufficiency and real-code replay."""
import json
from pathlib import Path
import subprocess
import sys

tool, *arguments = sys.argv[1:]
result = subprocess.run([sys.executable, tool, *arguments], capture_output=True, text=True)
if result.returncode:
    sys.exit(result.stdout + result.stderr)
out = Path(arguments[arguments.index("--out") + 1])
report = json.loads((out / "trace-plan.json").read_text())
assert report["status"] == "certified"
assert report["selected_mask"] == 62, "backend return should be derived from retained observations"
assert report["inclusion_minimal"] and not report["global_minimum_claimed"]
assert report["eliminations"] == [{"field": "read.result", "from_mask": 63, "to_mask": 62}]
assert len(report["minimality_witnesses"]) == 5
for witness in report["minimality_witnesses"]:
    native = witness["native"]
    assert native["trace_equal"] and not native["contract_equal"]
errno = next(w for w in report["minimality_witnesses"] if w["required_field"] == "errno.value")
assert errno["native"]["left"]["errno"] != errno["native"]["right"]["errno"]
for check in report["checks"]:
    if check["status"] in ("sufficient", "replay_verified"):
        assert check["completed_paths"] > 0 and check["partially_completed_paths"] == 0
        assert check["native_replayed_tests"] > 0
assert report["checks"][-1]["status"] == "replay_verified"
print(result.stdout)
print("bounded trace sufficiency, omission witnesses and transcript replay verified")
