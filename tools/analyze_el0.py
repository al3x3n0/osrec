#!/usr/bin/env python3
"""Discover conservative function closures for host EL0 extraction from LLVM IR."""
import argparse
from collections import deque
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_boundaries(path, functions, root):
    if path is None:
        return {}, None
    data = path.read_bytes()
    document = json.loads(data)
    if (not isinstance(document, dict) or set(document) != {"format", "boundaries"}
            or document["format"] != "osrec-el0-boundaries-v1"
            or not isinstance(document["boundaries"], dict)):
        raise ValueError("unsupported boundary manifest")
    for name, contract in document["boundaries"].items():
        if name == root or name not in functions or name.startswith("llvm."):
            raise ValueError(f"invalid boundary symbol: {name}")
        if (not isinstance(contract, dict) or set(contract) != {"reason", "implementation"}
                or any(not isinstance(v, str) or not v.strip() for v in contract.values())):
            raise ValueError(f"boundary {name} needs a reason and implementation description")
    return document["boundaries"], digest(data)


def expanded_calls(call):
    if "targets" not in call:
        return [call]
    edges = []
    for target in call["targets"]:
        edge = {key: value for key, value in call.items() if key not in {"targets", "kind"}}
        edges.append(dict(edge, **target, indirect_callsite=True))
    if not call["targets_complete"]:
        edges.append(call)
    return edges


def closure(functions, root, boundaries, kept_root=None):
    paths = {root: [root]}
    queue = deque([root])
    included, edges, cuts, blockers, requirements, callbacks = [], [], [], [], [], []
    while queue:
        name = queue.popleft()
        function = functions[name]
        included.append(name)
        path = paths[name]
        def selected(site):
            return (name != root or kept_root is None or "instruction" not in site
                    or site["instruction"] in kept_root)
        for issue in function["issues"]:
            if selected(issue):
                blockers.append(dict(issue, function=name, call_path=path))
        for memory in function["memory"]:
            if selected(memory):
                requirements.append(dict(memory, kind="memory_contract", function=name,
                                         call_path=path))
        for reference in function["global_references"]:
            requirements.append(dict(reference, kind="global_binding", function=name,
                                     call_path=path))
        if function["pointer_arguments"]:
            requirements.append({"kind": "pointer_arguments", "function": name,
                                 "arguments": function["pointer_arguments"], "call_path": path})
        for call in function["calls"]:
            if not selected(call):
                continue
            if "targets" in call:
                callbacks.append(dict(call, function=name, call_path=path))
                requirements.append({"kind": "callback_target_set", "function": name,
                                     "instruction": call["instruction"], "call_path": path,
                                     "targets": [target["callee"] for target in call["targets"]],
                                     "targets_complete": call["targets_complete"]})
            for expanded in expanded_calls(call):
                callee = expanded.get("callee")
                edge = dict(expanded, caller=name)
                edges.append(edge)
                if callee in boundaries:
                    cuts.append(dict(edge, contract=boundaries[callee], call_path=path + [callee]))
                elif expanded["kind"] == "direct":
                    if callee not in paths:
                        paths[callee] = path + [callee]
                        queue.append(callee)
                elif expanded["kind"] in {"external", "intrinsic"}:
                    blockers.append(dict(edge, kind="unmodeled_dependency",
                                         detail=f"{expanded['kind']} dependency has no reviewed implementation",
                                         call_path=path + [callee]))
                # Opaque assembly/indirect calls already have site-specific issues.
    cycles = recursive_edges(included, edges)
    if cycles:
        requirements.append({"kind": "recursion_bound", "detail": "bound stack use and termination"})
    status = ("requires_review" if blockers else
              "candidate_with_models" if cuts else
              "candidate_with_state" if requirements else "computation_candidate")
    domains = {"architecture_or_address_review": [], "ordering_review": [],
               "dependency_or_runtime_review": [], "environment_state_review": []}
    for blocker in blockers:
        kind = blocker["kind"]
        domain = ("ordering_review" if kind == "atomic_ordering" else
                  "architecture_or_address_review" if kind in
                  {"inline_assembly", "architecture_entry", "calling_convention",
                   "integer_address", "address_space"} else
                  "environment_state_review" if kind in {"volatile_access", "thread_local_state"} else
                  "dependency_or_runtime_review")
        domains[domain].append(blocker)
    return {"root": root, "classification": status, "included_functions": sorted(included),
            "call_paths": paths, "call_edges": edges, "model_boundaries": cuts,
            "blockers": blockers, "state_requirements": requirements,
            "review_domains": domains, "callback_sites": callbacks, "recursive_edges": cycles}


def instruction_slice(functions, root, boundaries):
    if "instruction_graph" not in functions[root]:
        raise ValueError("LLVM plugin did not produce the requested instruction graph")
    graph = {record["instruction"]: record for record in functions[root]["instruction_graph"]}
    seeds = [record for record in graph.values() if record["mandatory_reason"]]
    kept, pending = set(), [seed["instruction"] for seed in seeds]
    while pending:
        index = pending.pop()
        if index in kept:
            continue
        kept.add(index)
        pending.extend(graph[index]["data_dependencies"])
        pending.extend(graph[index]["memory_dependencies"])
    return {"criterion": "return_and_observable_effects", "root": root,
            "control_policy": "retain_all_terminators_and_their_dependencies",
            "interprocedural_policy": "retain_whole_callee_closures",
            "extraction_applied": False, "equivalence_verified": False,
            "total_instructions": len(graph), "retained_instructions": len(kept),
            "mandatory_seeds": [{"instruction": record["instruction"],
                                  "reason": record["mandatory_reason"]} for record in seeds],
            "kept": [record for index, record in graph.items() if index in kept],
            "omitted_candidates": [record for index, record in graph.items() if index not in kept],
            "candidate_closure": closure(functions, root, boundaries, kept)}


def recursive_edges(included, edges):
    """Iterative DFS: report actual directed back edges without unrolling stacks."""
    names = set(included)
    graph = {name: [] for name in included}
    for edge in edges:
        if edge.get("callee") in names and edge["kind"] == "direct":
            graph[edge["caller"]].append(edge["callee"])
    colors, cycles = {}, []
    for root in included:
        if root in colors:
            continue
        colors[root] = 1
        pending = [(root, iter(graph[root]))]
        while pending:
            name, children = pending[-1]
            child = next(children, None)
            if child is None:
                colors[name] = 2
                pending.pop()
            elif colors.get(child) == 1:
                cycles.append({"caller": name, "callee": child})
            elif child not in colors:
                colors[child] = 1
                pending.append((child, iter(graph[child])))
    return cycles


def analyze(args):
    data = args.module.read_bytes()
    pipeline = "osrec-el0-facts"
    if args.slice_return:
        if not re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$-]*", args.root):
            raise ValueError("instruction slicing needs a simple LLVM root symbol")
        pipeline += f"<{args.root}>"
    with tempfile.TemporaryDirectory(prefix="osrec-el0-") as directory:
        snapshot = Path(directory) / ("input.ll" if args.module.suffix == ".ll" else "input.bc")
        snapshot.write_bytes(data)
        result = subprocess.run([str(args.opt), "-load-pass-plugin", str(args.plugin.resolve()),
                                 f"-passes={pipeline}", "-disable-output", str(snapshot)],
                                text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError(f"LLVM analysis failed: {result.stderr.strip()}")
    facts = json.loads(result.stderr)
    if facts.get("format") != "osrec-el0-facts-v2":
        raise ValueError("unexpected LLVM analysis format")
    functions = {function["name"]: function for function in facts["functions"]}
    if args.root not in functions or functions[args.root]["declaration"]:
        raise ValueError("root must name a function with an available body")
    boundaries, boundary_hash = load_boundaries(args.boundaries, functions, args.root)
    selected = closure(functions, args.root, boundaries)
    sliced = instruction_slice(functions, args.root, boundaries) if args.slice_return else None
    candidates = []
    for name in selected["included_functions"]:
        item = closure(functions, name, boundaries)
        candidates.append({"root": name, "classification": item["classification"],
                           "functions": len(item["included_functions"]),
                           "blockers": len(item["blockers"]),
                           "state_requirements": len(item["state_requirements"]),
                           "model_boundaries": len(item["model_boundaries"])})
    if facts["module_assembly"]:
        issue = {"kind": "module_assembly", "detail": "module assembly is unclassified"}
        selected["blockers"].append(issue)
        selected["review_domains"]["architecture_or_address_review"].append(issue)
        selected["classification"] = "requires_review"
        if sliced:
            sliced["candidate_closure"]["blockers"].append(issue)
            sliced["candidate_closure"]["review_domains"]["architecture_or_address_review"].append(issue)
            sliced["candidate_closure"]["classification"] = "requires_review"
        for candidate in candidates:
            candidate["classification"] = "requires_review"
            candidate["blockers"] += 1
    return {"format": "osrec-el0-analysis-v2", "analysis_only": True,
            "function_contracts": {name: {key: functions[name][key] for key in
                                          ("return_type", "argument_types", "variadic", "calling_convention", "verification_obstacles")}
                                   for name in selected["included_functions"]},
            "native_execution_verified": False, "replay_equivalence_verified": False,
            "slice_granularity": ("root_instruction_slice_and_whole_callee_closures" if sliced
                                  else "whole_function_call_closure"),
            "asynchronous_roots_included": False,
            "input_sha256": digest(data), "boundary_manifest_sha256": boundary_hash,
            "analyzer_sha256": digest(Path(__file__).read_bytes()),
            "plugin_sha256": digest(args.plugin.read_bytes()),
            "llvm_version": facts["llvm_version"], "target": facts["target"],
            "data_layout": facts["data_layout"], "module_ir_sha256": facts["module_ir_sha256"],
            "assumptions": ["compiler-visible IR, available direct callees and proven finite callback sets only",
                            "all IR branches included; static call paths are not captured call stacks",
                            "boundary descriptions are proposals, not verified implementations",
                            "candidate requires well-defined execution, compatible ABI/layout and host code generation",
                            "memory must be valid, initialized and relocated; hidden writers require modeling"],
            "selected_slice": selected, "candidate_slices": candidates, "instruction_slice": sliced,
            "boundary_definitions": boundaries,
            "unused_boundaries": sorted(set(boundaries) -
                                         {cut["callee"] for cut in selected["model_boundaries"]})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path, help="linked LLVM 22 bitcode or textual IR")
    parser.add_argument("--root", required=True)
    parser.add_argument("--opt", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--boundaries", type=Path)
    parser.add_argument("--slice-return", action="store_true",
                        help="backward-slice the root's returns while retaining control flow and observable effects")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args)
        encoded = json.dumps(report, indent=2) + "\n"
        if args.out:
            protected = {args.module.resolve(), args.plugin.resolve(), args.opt.resolve()}
            if args.boundaries:
                protected.add(args.boundaries.resolve())
            if args.out.resolve() in protected:
                raise ValueError("output cannot overwrite an analysis input")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(encoded)
            selected = report["selected_slice"]
            print(f"{args.root}: {selected['classification']}; "
                  f"{len(selected['included_functions'])} functions, "
                  f"{len(selected['blockers'])} blockers, "
                  f"{len(selected['model_boundaries'])} model boundaries\n{args.out}")
            if report["instruction_slice"]:
                sliced = report["instruction_slice"]
                print(f"instruction candidate: {sliced['retained_instructions']}/"
                      f"{sliced['total_instructions']} retained; extraction not applied")
        else:
            print(encoded, end="")
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"EL0 analysis rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
