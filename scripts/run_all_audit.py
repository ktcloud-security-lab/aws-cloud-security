import subprocess
import re
import sys
import csv
from pathlib import Path
from datetime import datetime
from collections import Counter

VPC = "vpc-063a3a54bd0d5907a"

jobs = [
    ("N01_N02", ["--vpc-id", VPC]),
    ("N03_N04", ["--config", "scripts/approved_rules.json"]),
    ("N05", []),
    ("N06", []),
    ("N07", ["--vpc-id", VPC, "--alb-name", "404-web-alb"]),
    ("N08", ["--vpc-id", VPC])
]

names = {
    "N-01": "Public SG Rules",
    "N-02": "Admin Port Exposure",
    "N-03": "DB Access Control",
    "N-04": "Unnecessary Ports",
    "N-05": "Public IP Assignment",
    "N-06": "Subnet and Routing",
    "N-07": "ALB Access Control",
    "N-08": "Unauthorized Ingress"
}

results = {}
stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
folder = Path("reports") / f"integrated_{stamp}"
folder.mkdir(parents=True, exist_ok=True)

print("=" * 72)
print("          TEAM 404 - AWS SECURITY AUDIT")
print("=" * 72)
print("Mode   : Read Only")
print("Region : ap-northeast-2")
print("Policy : Stage 3 Baseline")
print("-" * 72)

for job, args in jobs:
    file = f"scripts/{job}_cloud_network_audit.py"

    print(f"Running {job} ...", flush=True)

    proc = subprocess.run(
        [sys.executable, file] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    output = proc.stdout

    (folder / f"{job}.log").write_text(
        output, encoding="utf-8"
    )

    if job == "N01_N02":
        for check in ["N-01", "N-02"]:
            match = re.search(
                rf"{check}: PASS (\d+) / REVIEW (\d+) / FAIL (\d+)",
                output
            )
            if match:
                results[check] = tuple(map(int, match.groups()))

    elif job == "N03_N04":
        mapping = {
            "양호": "PASS",
            "확인 필요": "REVIEW",
            "취약": "FAIL"
        }

        for check in ["N-03", "N-04"]:
            counts = Counter()

            for line in output.splitlines():
                parts = [p.strip() for p in line.split("|")]

                if len(parts) >= 4 and parts[0] == check:
                    status = mapping.get(parts[2])
                    if status:
                        counts[status] += 1

            if counts:
                results[check] = (
                    counts["PASS"],
                    counts["REVIEW"],
                    counts["FAIL"]
                )

    else:
        match = re.search(
            r"SUMMARY: PASS=(\d+) FAIL=(\d+) REVIEW=(\d+)",
            output
        )

        if match:
            p, f, r = map(int, match.groups())
            results["N-" + job[1:]] = (p, r, f)


# Detailed audit results
details = {check: [] for check in names}

for job, args in jobs:
    logfile = folder / f"{job}.log"
    if not logfile.exists():
        continue

    current = None

    for line in logfile.read_text(
        encoding="utf-8"
    ).splitlines():

        # N-01 / N-02
        match = re.match(
            r"^\[(N-\d{2})\]\s+(PASS|REVIEW|FAIL)\s+(.*)",
            line
        )
        if match:
            check, status, message = match.groups()
            current = [status, message, []]
            details[check].append(current)
            continue

        # N-03 / N-04
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4 and parts[0] in ("N-03", "N-04"):
            status = {
                "양호": "PASS",
                "확인 필요": "REVIEW",
                "취약": "FAIL"
            }.get(parts[2])

            if status:
                current = [
                    status,
                    parts[1] + " | " + parts[3],
                    []
                ]
                details[parts[0]].append(current)
            continue

        # N-05 ~ N-08
        match = re.match(
            r"^\[(PASS|REVIEW|FAIL)\s*\]\s+"
            r"(N-?\d{2}(?:-\d{2})?)\s+(.*)",
            line
        )

        if match:
            status, code, message = match.groups()
            check = "N-" + re.search(r"\d{2}", code).group()

            current = [status, code + " | " + message, []]
            details[check].append(current)
            continue

        # Additional evidence
        if current is not None and line.startswith("  "):
            if line.strip():
                current[2].append(line.strip())

colors = {
    "PASS": "\033[92m",
    "REVIEW": "\033[93m",
    "FAIL": "\033[91m"
}

reset = "\033[0m"
blue = "\033[96m"

import textwrap

print()
print("=" * 72)
print("                  DETAILED AUDIT RESULTS")
print("=" * 72)

for check, name in names.items():
    print()
    print(f"{blue}{check} | {name}{reset}")
    print("-" * 72)

    if not details[check]:
        print("No detailed results collected.")

    for status, message, evidence in details[check]:
        wrapped = textwrap.wrap(message, width=61) or [""]

        print(
            f"{colors[status]}[{status:<6}]{reset} "
            f"{wrapped[0]}"
        )

        for line in wrapped[1:]:
            print("         " + line)

        for item in evidence:
            for line in textwrap.wrap(item, width=59):
                print("           " + line)

    if check in results:
        p, r, f = results[check]
        print("-" * 72)
        print(
            f"PASS: {p} | REVIEW: {r} | FAIL: {f}"
        )


# Save detailed audit results
detail_file = folder / "details.csv"

with detail_file.open(
    "w", newline="", encoding="utf-8-sig"
) as file:
    writer = csv.writer(file)

    writer.writerow([
        "CHECK_ID",
        "CHECK_ITEM",
        "STATUS",
        "TARGET_AND_DETAILS",
        "EVIDENCE"
    ])

    for check, name in names.items():
        for status, message, evidence in details[check]:
            writer.writerow([
                check,
                name,
                status,
                message,
                " | ".join(evidence)
            ])

print()
print("=" * 72)
print("                   AUDIT SUMMARY")
print("=" * 72)

header = "{:<7} {:<27} {:>6} {:>8} {:>6}"

print(header.format(
    "ID", "CHECK ITEM", "PASS", "REVIEW", "FAIL"
))
print("-" * 72)

totals = [0, 0, 0]
rows = []
errors = []

for check, name in names.items():
    if check not in results:
        print(f"{check:<7} {name:<27} ERROR")
        rows.append([check, name, "", "", "", "ERROR"])
        errors.append(check)
        continue

    p, r, f = results[check]

    print(header.format(check, name, p, r, f))

    totals[0] += p
    totals[1] += r
    totals[2] += f

    rows.append([check, name, p, r, f, "COMPLETED"])

print("-" * 72)
print(header.format("TOTAL", "", *totals))
print("=" * 72)

with (folder / "summary.csv").open(
    "w", newline="", encoding="utf-8-sig"
) as file:
    writer = csv.writer(file)
    writer.writerow([
        "ID", "CHECK_ITEM", "PASS",
        "REVIEW", "FAIL", "EXECUTION"
    ])
    writer.writerows(rows)

print(f"Completed : {len(results)}/8 checks")
print(f"Report    : {folder}/summary.csv")
print(f"Details   : {folder}/details.csv")
print(f"Raw logs  : {folder}")
print("NOTE: Baseline differences require manual review.")
print("NOTE: No AWS resources were modified.")

if errors:
    print("Execution errors:", ", ".join(errors))
    sys.exit(1)
