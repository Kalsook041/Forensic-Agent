"""One-shot real local model checks against an independently measured PCAP."""
import argparse
import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import re
import time

from forensic_agent.agent.loop import analyze
from forensic_agent.evidence import Case
from forensic_agent.evidence.store import sha256_file, write_json
from forensic_agent.evidence.values import evidence_value, supports_answer
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.settings import load_settings
from forensic_agent.tools.process import capture, clean_environment
from forensic_agent.tools.runner import run_tool


def answers_pass(case, question, reference):
    """Require cited full-capture statistics, not merely coincidentally correct values."""
    if question not in {"honeynet-q1", "honeynet-q3"}:
        return False
    if case.manifest["state"] != "completed" or case.verify_current():
        return False
    evidence = {row["id"]: (step, row) for step in case.manifest["steps"] for row in step["evidence"]}
    addresses, sessions, ip_citations = set(), [], 0
    for answer in case.manifest["answers"]:
        field = answer["field"]
        ip_field = field == "ip_addresses" or re.fullmatch(r"ip_addresses\[[0-9]{1,6}\]", field)
        if not (ip_field if question == "honeynet-q1" else field == "tcp_session_count"):
            continue
        found = evidence.get(answer["evidence_id"])
        if not found:
            return False
        step, row = found
        request, data = step["request"], row["data"]
        scope, params = data.get("scope", {}), request.get("params", {})
        if (request["tool_id"] != "pcap" or request["source_id"] != case.manifest["root_id"]
                or row["source_id"] != case.manifest["root_id"]
                or row["locator"].get("kind") != "pcap_summary"
                or step["result"]["status"] not in {"ok", "partial"}
                or step["integrity"]["issues"] or not supports_answer(step, row)
                or scope.get("kind") != "capture" or scope.get("protocol") != "overview"
                or params.get("protocol", "overview") != "overview"
                or scope.get("ip_address") not in {None, ""} or scope.get("tcp_stream") is not None
                or params.get("ip_address") not in {None, ""} or params.get("tcp_stream") is not None):
            return False
        try:
            value = evidence_value(data, field)
        except KeyError:
            return False
        if json.dumps(value, sort_keys=True) != json.dumps(answer["value"], sort_keys=True):
            return False
        if question == "honeynet-q1":
            if (data.get("ip_statistics_complete") is not True or data.get("ip_addresses_complete") is not True
                    or not isinstance(data.get("ip_addresses"), list)
                    or sorted(data["ip_addresses"]) != sorted(reference["ip_addresses"])):
                return False
            values = value if isinstance(value, list) else [value]
            if not all(isinstance(address, str) for address in values):
                return False
            addresses.update(values)
            ip_citations += 1
        else:
            if data.get("tcp_statistics_complete") is not True or type(value) is not int:
                return False
            sessions.append(value)
    return (addresses == set(reference["ip_addresses"]) and ip_citations > 0 if question == "honeynet-q1"
            else bool(sessions) and all(value == reference["tcp_session_count"] for value in sessions))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True, type=Path)
    options = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = project / "local-state/pcap-workflow-checks" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True)
    settings = load_settings(project / "config/default.toml")
    sample = options.sample.resolve(strict=True)
    before = sha256_file(sample)
    # This reference is never included in model prompts or registered evidence.
    args = [settings.tools.tshark, "-n", "-r", str(sample), "-T", "fields", "-E", "header=y",
            "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y", "-E", "occurrence=a"]
    for field in ("frame.number", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.stream"):
        args += ["-e", field]
    native = capture(args, cwd=output, env=clean_environment(output), timeout=180, max_output=settings.limits.output_bytes,
                     stdout_path=output / "reference.stdout", stderr_path=output / "reference.stderr")
    if native.returncode != 0 or native.stopped:
        write_json(output / "reference-failed.json", {"returncode": native.returncode, "stopped": native.stopped})
        return 2
    rows = list(csv.DictReader(io.StringIO(native.stdout.decode("utf-8-sig")), delimiter="\t"))
    ips = sorted({address for row in rows for key in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst")
                  for address in row[key].split(",") if address})
    streams = {stream for row in rows for stream in row["tcp.stream"].split(",") if stream}
    reference = {"sample_sha256": before, "packet_count": len(rows), "ip_addresses": ips,
                 "tcp_session_count": len(streams), "source": "Independent full fixed-field TShark output"}
    write_json(output / "reference.json", reference)
    case = Case.create(sample, settings, "人工检查完整统计与帧分页；不计入模型解题成绩")
    step = run_tool(case, ToolRequest(tool_id="pcap", source_id="s00001", params={"protocol": "overview", "limit": 3}))
    summary = step["evidence"][0]["data"] if step["evidence"] else {}
    adapter_ok = (summary.get("packet_count") == len(rows) and summary.get("tcp_session_count") == len(streams)
                  and sorted(summary.get("ip_addresses", [])) == ips and not case.verify_current())
    write_json(output / "adapter-check.json", {"passed": adapter_ok, "summary": summary,
               "case": str(case.directory), "status": step["result"]["status"]})
    outcomes = []
    for name, question in (
        ("honeynet-q1", "这是 Honeynet Forensic Challenge 2010 第1题的PCAP检材。哪些系统（IP地址）参与了此次网络通信？请列出检材中实际出现的IP地址并逐项引用证据。"),
        ("honeynet-q3", "这是 Honeynet Forensic Challenge 2010 第3题的PCAP检材。整个抓包文件中共有多少个TCP会话？请给出会话数量并引用支持这一数量的证据，不要把某条报文的tcp.stream编号直接当作数量。"),
    ):
        case = Case.create(sample, settings, question)
        start = time.monotonic()
        analyze(case, progress=lambda line: print(name + ": " + line, flush=True))
        report = generate_report(case)
        answers = case.manifest["answers"]
        outcome = {"test": name, "passed": answers_pass(case, name, reference),
                   "state": case.manifest["state"], "answers": answers, "warnings": case.manifest["warnings"],
                   "case": str(case.directory), "report": str(report), "elapsed_seconds": time.monotonic() - start,
                   "tools": [step["request"] for step in case.manifest["steps"]]}
        outcomes.append(outcome)
        write_json(output / (name + ".json"), outcome)
        print(json.dumps(outcome, ensure_ascii=False), flush=True)
    unchanged = sha256_file(sample) == before
    passed = adapter_ok and unchanged and all(item["passed"] for item in outcomes)
    write_json(output / "results.json", {"passed": passed, "cases": outcomes, "adapter_passed": adapter_ok,
               "sample_unchanged": unchanged, "attempt_policy": "One analyze per question; all internal responses preserved"})
    print(str(output), flush=True)
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
