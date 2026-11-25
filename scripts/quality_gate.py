#!/usr/bin/env python3
"""Quality Gate B (bloqueante). Fail-closed: informe ausente o invalido => bloqueo."""
import json
import os
import sys
import xml.etree.ElementTree as ET

REPORTS = "reports"
MAX_CRITICAL = int(os.environ.get("GATE_MAX_CRITICAL", "0"))
MAX_HIGH = int(os.environ.get("GATE_MAX_HIGH", "0"))


def fail_closed(path, err):
    # abortar con fallo seguro si falta un informe o esta corrupto
    print(f"[GATE][ERROR] Informe {path} no disponible o invalido: {err}")
    print("[GATE] Fail-closed: sin informe no se puede garantizar la seguridad -> BLOQUEO")
    sys.exit(2)


def load_json(name):
    path = os.path.join(REPORTS, name)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        fail_closed(path, e)


def load_xml(name):
    path = os.path.join(REPORTS, name)
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError) as e:
        fail_closed(path, e)


def count_npm(d):
    v = d.get("metadata", {}).get("vulnerabilities", {})
    return v.get("critical", 0), v.get("high", 0)


def count_trivy(d):
    crit = high = 0
    for r in d.get("Results", []):
        for item in (r.get("Vulnerabilities") or []) + (r.get("Misconfigurations") or []) + (r.get("Secrets") or []):
            sev = item.get("Severity")
            if sev == "CRITICAL":
                crit += 1
            elif sev == "HIGH":
                high += 1
    return crit, high


def count_zap(root):
    # zap no tiene nivel critical el codigo de riesgo tres equivale a high
    high = sum(
        1
        for alert in root.findall(".//alertitem")
        if (alert.findtext("riskcode") or "").strip() == "3"
    )
    return 0, high


SOURCES = [
    ("SCA  (npm audit)", "sca-dependencies-report.json", load_json, count_npm),
    ("IaC  (Trivy config)", "trivy-iac-report.json", load_json, count_trivy),
    ("Imagen (Trivy image)", "trivy-image-report.json", load_json, count_trivy),
    ("DAST (OWASP ZAP)", "zap-report.xml", load_xml, count_zap),
]

total_c = total_h = 0
print(f"{'Herramienta':<22}{'CRITICAL':>10}{'HIGH':>8}")
for label, fname, loader, fn in SOURCES:
    c, h = fn(loader(fname))
    total_c += c
    total_h += h
    print(f"{label:<22}{c:>10}{h:>8}")
print(f"{'TOTAL':<22}{total_c:>10}{total_h:>8}")
print(f"Umbrales: CRITICAL <= {MAX_CRITICAL}, HIGH <= {MAX_HIGH}")

summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as f:
        f.write(f"### Quality Gate B\nCRITICAL: {total_c} (max {MAX_CRITICAL}) | HIGH: {total_h} (max {MAX_HIGH})\n")

if total_c > MAX_CRITICAL or total_h > MAX_HIGH:
    print("[GATE] BLOQUEO: umbral superado. El pipeline se detiene, no se despliega en produccion.")
    sys.exit(1)
print("[GATE] OK: umbral respetado.")