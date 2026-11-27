#!/usr/bin/env python3
import datetime
import os
from pathlib import Path
import requests

# configuracion de informes generados en el pipeline con titulo unico por test
SCANS = [
    {
        "file": Path("reports/semgrep-report.json"),
        "scan_type": "Semgrep JSON Report",
        "test_title": "SAST - Semgrep",
    },
    {
        "file": Path("reports/sca-dependencies-report.json"),
        "scan_type": "NPM Audit v7+ Scan",
        "test_title": "SCA - npm audit",
    },
    {
        "file": Path("reports/trivy-iac-report.json"),
        "scan_type": "Trivy Scan",
        "test_title": "IaC - Trivy Config",
    },
    {
        "file": Path("reports/trivy-image-report.json"),
        "scan_type": "Trivy Scan",
        "test_title": "Container - Trivy Image",
    },
    {
        "file": Path("reports/zap-report.xml"),
        "scan_type": "ZAP Scan",
        "test_title": "DAST - OWASP ZAP",
    },
]


def upload_report(endpoint: str, headers: dict, engagement_id: str, scan: dict, scan_date: str) -> bool:
    # comprobar existencia y contenido del fichero de reporte
    report_path = scan["file"]
    if not report_path.exists() or report_path.stat().st_size == 0:
        print(f"[SKIP] No existe o esta vacio: {report_path}")
        return False

    # reimportacion automatica para evitar duplicados de tests y marcar mitigados
    data = {
        "product_name": "OWASP Juice Shop",
        "engagement_name": "GitHub Actions CI/CD",
        "product_type_name": "Research and Development",
        "auto_create_context": "true",
        "scan_type": scan["scan_type"],
        "test_title": scan["test_title"],
        "scan_date": scan_date,
        "active": "true",
        "verified": "false",
        "close_old_findings": "true",
        "minimum_severity": "Info",
    }

    mime = "application/xml" if report_path.suffix == ".xml" else "application/json"
    with report_path.open("rb") as fh:
        files = {"file": (report_path.name, fh, mime)}
        resp = requests.post(
            endpoint,
            headers=headers,
            data=data,
            files=files,
            timeout=60,
        )

    if resp.status_code in (200, 201):
        print(f"[OK] Reimportado {report_path} ({scan['test_title']}) -> HTTP {resp.status_code}")
        return True

    raise SystemExit(
        f"[ERROR] Fallo la subida de {report_path} ({scan['scan_type']}): "
        f"HTTP {resp.status_code} - {resp.text}"
    )


def main() -> None:
    # lectura de variables de entorno inyectadas desde github secrets
    base_url = os.environ.get("DEFECTDOJO_URL", "").strip().rstrip("/")
    api_key = os.environ.get("DEFECTDOJO_API_KEY", "").strip()
    engagement_id = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "").strip()

    if not base_url or not api_key or not engagement_id:
        raise SystemExit(
            "Faltan variables de entorno requeridas: DEFECTDOJO_URL, "
            "DEFECTDOJO_API_KEY o DEFECTDOJO_ENGAGEMENT_ID."
        )

    endpoint = f"{base_url}/api/v2/reimport-scan/"
    # incluir cabecera referer para evitar rechazo csrf de django tras proxy https
    headers = {
        "Authorization": f"Token {api_key}",
        "Referer": base_url,
    }
    today = datetime.date.today().isoformat()

    uploaded = 0
    for scan in SCANS:
        if upload_report(endpoint, headers, engagement_id, scan, today):
            uploaded += 1

    print(f"Total de informes reimportados en DefectDojo: {uploaded}")


if __name__ == "__main__":
    main()