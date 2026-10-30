#!/usr/bin/env python3
"""Verify exported scenarios run alone and reject corrupted construction data."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

tool, plan_arg, kernel, compiler = sys.argv[1:]
plan = Path(plan_arg).resolve()
PROVENANCE = "synthetic model capture; not recorded from a running kernel"


def invoke(out, source, capture=False, proof=plan, failure=None):
    command = [sys.executable, tool, "--plan", str(proof), "--kernel-root", kernel,
               "--compiler", compiler, "--out", str(out),
               "--capture" if capture else "--case", str(source)]
    result = subprocess.run(command, capture_output=True, text=True)
    if failure:
        assert result.returncode and failure in result.stderr, result.stdout + result.stderr
        assert not out.exists(), "failed construction published an executable"
        return
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def isolated(binary):
    with tempfile.TemporaryDirectory(prefix="osrec-alone-") as folder:
        root = Path(folder)
        copied = root / "scenario"
        shutil.copy2(binary, copied)
        assert list(root.iterdir()) == [copied]
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        output = subprocess.run([str(copied)], cwd=root, env=env, capture_output=True, text=True, check=True)
        description = json.loads(subprocess.run([str(copied), "--describe"], cwd=root, env=env,
                                                capture_output=True, text=True, check=True).stdout)
        assert output.stdout.startswith("scenario verified:")
        assert description["trace"]["mask"] == 62
        assert description["trace"]["read_present"] == description["trace"]["read_result"] == 0
        assert description["provenance"] == PROVENANCE
        assert "Redistributions in binary form" in description["kernel_license"]
        assert "Huawei" in description["kernel_license"]
        assert description["scheduler_irq_execution"] is False
        return description


cases = [
    ("full", 3, 8, 0, 0, 4, 4, 0),
    ("short", 3, 8, 0, 0, 2, 2, 0),
    ("empty", 3, 8, 0, 0, 0, 0, 0),
    ("zero_request", 1, 0, 1, 2, 4, 0, 0),
    ("bad_fd", 1, 8, 0, 2, 4, -1, 9),
    ("bad_range", 3, 9, 0, 0, 4, -1, 14),
    ("null", 3, 1, 1, 0, 4, -1, 14),
    ("eintr", 3, 8, 0, 1, 4, -1, 4),
    ("eio", 3, 8, 0, 2, 4, -1, 5),
]

with tempfile.TemporaryDirectory(prefix="osrec-standalone-tests-") as folder:
    root = Path(folder)
    short_capture = None
    for name, fd, count, null, mode, limit, expected_return, expected_errno in cases:
        case = {"format": "osrec-sysread-case-v1", "provenance": PROVENANCE,
                "request": {"fd": fd, "count": count, "null_buffer": null},
                "environment": {"mode": mode, "success_limit": limit, "payload": "41424344"}}
        source = root / f"{name}.json"
        source.write_text(json.dumps(case))
        binary = root / name
        result = invoke(binary, source)
        assert result["system_libraries"], "platform runtime dependencies should be disclosed"
        captured = json.loads(Path(str(binary) + ".capture.json").read_text())
        if name == "short":
            short_capture = captured
            assert captured["trace"]["payload"] == "41420000", "unused environment bytes leaked into trace"
        source.unlink()
        Path(str(binary) + ".capture.json").unlink()
        Path(str(binary) + ".manifest.json").unlink()
        description = isolated(binary)
        assert description["expected"]["return"] == expected_return
        assert description["expected"]["errno"] == expected_errno

    # Repackage retained observations without the original environment case.
    source = root / "capture.json"
    source.write_text(json.dumps(short_capture))
    repacked = root / "repacked"
    invoke(repacked, source, capture=True)
    isolated(repacked)

    bad = json.loads(json.dumps(short_capture))
    bad["expected"]["return"] = 3
    source.write_text(json.dumps(bad))
    invoke(root / "bad_expected", source, capture=True, failure="scenario execution diverged")

    bad = json.loads(json.dumps(short_capture))
    bad["trace"]["payload"] = "58420000"
    source.write_text(json.dumps(bad))
    invoke(root / "bad_payload", source, capture=True, failure="scenario execution diverged")

    bad = json.loads(json.dumps(short_capture))
    bad["trace"]["read_result"] = 2
    source.write_text(json.dumps(bad))
    invoke(root / "hidden_return", source, capture=True, failure="omitted read observation contains information")

    bad = json.loads(json.dumps(short_capture))
    bad["trace"]["original_environment"] = {"payload": "41424344"}
    source.write_text(json.dumps(bad))
    invoke(root / "extra_state", source, capture=True, failure="unsupported trace fields")

    # Metadata corruption must not bypass analysis or source identity checks.
    rejected_plan = root / "bad_plan.json"
    original_plan = json.loads(plan.read_text())
    bad_plan = json.loads(json.dumps(original_plan))
    bad_plan["status"] = "uncertified"
    rejected_plan.write_text(json.dumps(bad_plan))
    invoke(root / "uncertified", source, capture=True, proof=rejected_plan,
           failure="completed, certified trace plan")

    bad_plan = json.loads(json.dumps(original_plan))
    bad_plan["inputs"]["integrations/liteos_a/models.c"] = "0" * 64
    rejected_plan.write_text(json.dumps(bad_plan))
    invoke(root / "stale_source", source, capture=True, proof=rejected_plan,
           failure="analyzed source changed")

print("9 independent scenario paths, capture-only repackaging and 6 rejection checks passed")
