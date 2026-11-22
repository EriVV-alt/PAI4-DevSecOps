import datetime
import os
from pathlib import Path
import requests

SCANS = [
    {
        "file": Path("reports/sca-dependencies-report.json"),
        "scan_type": "Node npm audit Scan",
    },
    {
        "file": Path("reports/trivy-iac-report.json"),
        "scan_type": "Trivy Scan",
    },
    {
        "file": Path("reports/trivy-image-report.json"),
        "scan_type": "Trivy Scan",
    },
    {
        "file": Path("reports/zap-report.json"),
        "scan_type": "ZAP Scan",
    },
]

def main() -> None:
    base_url = os.environ.get("DEFECTDOJO_URL", "").strip().rstrip("/")
    api_key = os.environ.get("DEFECTDOJO_API_KEY", "").strip()
    engagement_id = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "").strip()

    if not base_url or not api_key or not engagement_id:
        raise SystemExit(
            "Faltan variables de entorno requeridas: DEFECTDOJO_URL, "
            "DEFECTDOJO_API_KEY o DEFECTDOJO_ENGAGEMENT_ID."
        )

    endpoint = f"{base_url}/api/v2/import-scan/"
    headers = {"Authorization": f"Token {api_key}"}
    today = datetime.date.today().isoformat()

    uploaded = 0
    for scan in SCANS:
        report_path = scan["file"]
        if not report_path.exists() or report_path.stat().st_size == 0:
            print(f"[SKIP] No existe o está vacío: {report_path}")
            continue

        data = {
            "engagement": engagement_id,
            "scan_type": scan["scan_type"],
            "scan_date": today,
            "active": "true",
            "verified": "false",
            "close_old_findings": "false",
            "minimum_severity": "Info",
        }

        with report_path.open("rb") as fh:
            files = {"file": (report_path.name, fh, "application/json")}
            resp = requests.post(
                endpoint,
                headers=headers,
                data=data,
                files=files,
                timeout=60,
            )

        if resp.status_code in (200, 201):
            print(f"[OK] Subido {report_path} ({scan['scan_type']}) -> HTTP {resp.status_code}")
            uploaded += 1
        else:
            raise SystemExit(
                f"[ERROR] Falló la subida de {report_path} ({scan['scan_type']}): "
                f"HTTP {resp.status_code} - {resp.text}"
            )

    print(f"Total de informes importados en DefectDojo: {uploaded}")

if __name__ == "__main__":
    main()
    
