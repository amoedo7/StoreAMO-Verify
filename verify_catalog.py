#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "storeamo.catalog.v1"
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
PLATFORMS = {"android", "windows", "macos", "linux", "web", "ios", "other"}
STATUSES = {"development", "candidate", "verified", "deprecated"}
DOWNLOAD_STATUSES = {"candidate", "verified"}
USER_AGENT = "StoreAMO-Verify/2 (+https://github.com/amoedo7/StoreAMO-Verify)"

@dataclass
class Check:
    id: str
    level: str
    status: str
    message: str
    details: dict[str, Any] | None = None


def add(checks: list[Check], cid: str, level: str, ok: bool | None, message: str, details=None):
    status = "PASS" if ok is True else "FAIL" if ok is False else "SKIP"
    checks.append(Check(cid, level, status, message, details))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or p.stderr or "").strip()
    except Exception as exc:
        return 127, exc.__class__.__name__


def load_catalog(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_catalog(catalog: dict[str, Any], checks: list[Check]) -> None:
    add(checks, "catalog.schema", "L0", catalog.get("schema") == SCHEMA,
        f"schema esperado: {SCHEMA}", {"found": catalog.get("schema")})
    apps = catalog.get("apps")
    add(checks, "catalog.apps", "L0", isinstance(apps, list), "apps debe ser una lista")
    if not isinstance(apps, list):
        return

    ids: list[str] = []
    for idx, app in enumerate(apps):
        prefix = f"app[{idx}]"
        valid_obj = isinstance(app, dict)
        add(checks, f"{prefix}.object", "L0", valid_obj, "entrada de app válida")
        if not valid_obj:
            continue
        app_id = app.get("id")
        add(checks, f"{prefix}.id", "L0", isinstance(app_id, str) and bool(app_id), "id presente")
        if isinstance(app_id, str):
            ids.append(app_id)
        add(checks, f"{prefix}.name", "L0", isinstance(app.get("name"), str) and bool(app.get("name")), "name presente")
        add(checks, f"{prefix}.status", "L0", app.get("status") in STATUSES, "status reconocido", {"found": app.get("status")})
        supported = app.get("supported_platforms", [])
        add(checks, f"{prefix}.supported_platforms", "L0", isinstance(supported, list) and all(p in PLATFORMS for p in supported), "plataformas soportadas válidas")
        artifacts = app.get("artifacts")
        add(checks, f"{prefix}.artifacts", "L0", isinstance(artifacts, list), "artifacts debe ser una lista")
        if not isinstance(artifacts, list):
            continue
        seen_platform_version: set[tuple[str, str]] = set()
        for aidx, artifact in enumerate(artifacts):
            ap = f"{prefix}.artifact[{aidx}]"
            if not isinstance(artifact, dict):
                add(checks, f"{ap}.object", "L0", False, "artifact debe ser objeto")
                continue
            platform = artifact.get("platform")
            version = str(artifact.get("version", ""))
            add(checks, f"{ap}.platform", "L0", platform in PLATFORMS, "plataforma válida", {"found": platform})
            add(checks, f"{ap}.version", "L0", bool(version), "versión presente")
            url = artifact.get("url")
            add(checks, f"{ap}.https", "L0", isinstance(url, str) and url.startswith("https://"), "descarga por HTTPS")
            sha = artifact.get("sha256")
            add(checks, f"{ap}.sha256-format", "L0", isinstance(sha, str) and bool(SHA256_RE.fullmatch(sha)), "SHA-256 con formato válido")
            if platform == "android":
                add(checks, f"{ap}.application-id", "L0", bool(artifact.get("application_id")), "application_id declarado")
                add(checks, f"{ap}.version-code", "L0", str(artifact.get("version_code", "")).isdigit(), "version_code Android numérico", {"found": artifact.get("version_code")})
                add(checks, f"{ap}.size", "L0", isinstance(artifact.get("size_bytes"), int) and artifact.get("size_bytes", 0) > 0, "size_bytes declarado")
            key = (str(platform), version)
            add(checks, f"{ap}.duplicate", "L0", key not in seen_platform_version, "platform/version no duplicada")
            seen_platform_version.add(key)
            if artifact.get("verified") is True:
                add(checks, f"{ap}.verified-report", "L5", bool(artifact.get("verification_report")), "una release verificada referencia su reporte")

    add(checks, "catalog.unique-ids", "L0", len(ids) == len(set(ids)), "IDs de apps únicos")


def find_artifact(catalog: dict[str, Any], app_id: str, platform: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    for app in catalog.get("apps", []):
        if app.get("id") != app_id:
            continue
        candidates = [a for a in app.get("artifacts", []) if a.get("platform") == platform]
        if not candidates:
            return app, None
        return app, candidates[0]
    return None, None


def inspect_zip_apk(path: Path, checks: list[Check]) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            names = set(zf.namelist())
            add(checks, "android.zip-integrity", "L1", bad is None, "APK/ZIP íntegro", {"bad_entry": bad})
            add(checks, "android.manifest-present", "L1", "AndroidManifest.xml" in names, "AndroidManifest.xml presente")
            add(checks, "android.dex-present", "L1", any(n.startswith("classes") and n.endswith(".dex") for n in names), "DEX presente")
    except zipfile.BadZipFile:
        add(checks, "android.zip-integrity", "L1", False, "archivo no es un APK/ZIP válido")


def inspect_android(path: Path, artifact: dict[str, Any], checks: list[Check]) -> None:
    inspect_zip_apk(path, checks)
    aapt = shutil.which("aapt2") or shutil.which("aapt")
    if aapt:
        code, out = run([aapt, "dump", "badging", str(path)])
        if code == 0:
            package_match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", out)
            if package_match:
                package_name, version_code, version_name = package_match.groups()
                expected_package = artifact.get("application_id")
                add(checks, "android.application-id", "L2", package_name == expected_package, "applicationId coincide", {"expected": expected_package, "found": package_name})
                add(checks, "android.version-code", "L2", version_code == str(artifact.get("version_code", "")), "versionCode coincide", {"expected": artifact.get("version_code"), "found": version_code})
                add(checks, "android.version-name", "L2", version_name == str(artifact.get("version", "")), "versionName coincide", {"expected": artifact.get("version"), "found": version_name})
            else:
                add(checks, "android.badging", "L2", False, "no se pudo extraer package/version", {"output": out[:500]})
        else:
            add(checks, "android.badging", "L2", False, "aapt/aapt2 falló", {"output": out[:500]})
    else:
        add(checks, "android.badging", "L2", None, "aapt/aapt2 no disponible")

    apksigner = shutil.which("apksigner")
    if apksigner:
        code, out = run([apksigner, "verify", "--print-certs", str(path)])
        add(checks, "android.signature-valid", "L3", code == 0, "firma APK válida", {"output": out[:1200]})
        found = None
        if code == 0:
            for line in out.splitlines():
                if "SHA-256 digest:" in line:
                    found = line.split("SHA-256 digest:", 1)[1].strip().lower().replace(":", "")
                    break
            add(checks, "android.signing-cert-found", "L3", bool(found), "fingerprint SHA-256 de firma extraído", {"found": found})
        expected_cert = str(artifact.get("signing_cert_sha256") or "").lower().replace(":", "")
        if expected_cert and found:
            add(checks, "android.signing-cert", "L3", found == expected_cert, "certificado coincide", {"expected": expected_cert, "found": found})
        elif not expected_cert:
            add(checks, "android.signing-cert", "L3", None, "catálogo no declara signing_cert_sha256", {"found": found})
    else:
        add(checks, "android.signature-valid", "L3", None, "apksigner no disponible")


def verify_artifact(catalog: dict[str, Any], app_id: str, platform: str, path: Path, checks: list[Check]) -> None:
    app, artifact = find_artifact(catalog, app_id, platform)
    add(checks, "artifact.app-found", "L1", app is not None, "app existe en catálogo", {"app": app_id})
    if app is None:
        return
    add(checks, "artifact.entry-found", "L1", artifact is not None, "artifact existe para plataforma", {"platform": platform})
    if artifact is None:
        return
    verify_local_file(path, artifact, platform, checks)


def verify_local_file(path: Path, artifact: dict[str, Any], platform: str, checks: list[Check]) -> None:
    add(checks, "artifact.file-exists", "L1", path.is_file(), "archivo local existe", {"path": str(path)})
    if not path.is_file():
        return
    actual_sha = sha256_file(path)
    expected_sha = str(artifact.get("sha256", "")).lower()
    add(checks, "artifact.sha256", "L1", actual_sha == expected_sha, "SHA-256 coincide", {"expected": expected_sha, "found": actual_sha})
    expected_size = artifact.get("size_bytes")
    if isinstance(expected_size, int):
        add(checks, "artifact.size", "L1", path.stat().st_size == expected_size, "tamaño coincide", {"expected": expected_size, "found": path.stat().st_size})
    else:
        add(checks, "artifact.size", "L1", None, "catálogo no declara size_bytes")
    if platform == "android" or path.suffix.lower() == ".apk":
        inspect_android(path, artifact, checks)


def download_artifact(url: str, target: Path, checks: list[Check]) -> bool:
    add(checks, "download.https", "L1", url.startswith("https://"), "URL pública usa HTTPS", {"url": url})
    if not url.startswith("https://"):
        return False
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=45) as response, target.open("wb") as out:
            status = getattr(response, "status", None) or response.getcode()
            final_url = response.geturl()
            content_type = (response.headers.get("Content-Type") or "").lower()
            add(checks, "download.http", "L1", 200 <= int(status) < 300, "descarga anónima responde 2xx", {"status": status, "final_url": final_url, "content_type": content_type})
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        add(checks, "download.bytes", "L1", target.stat().st_size > 0, "descarga devolvió bytes reales", {"size_bytes": target.stat().st_size})
        with target.open("rb") as f:
            head = f.read(256).lstrip().lower()
        htmlish = head.startswith(b"<!doctype html") or head.startswith(b"<html")
        add(checks, "download.not-html", "L1", not htmlish, "descarga no es HTML/login/error")
        return all(c.status != "FAIL" for c in checks if c.id.startswith("download."))
    except urllib.error.HTTPError as exc:
        add(checks, "download.http", "L1", False, "descarga anónima falló", {"status": exc.code, "reason": str(exc.reason), "url": url})
    except Exception as exc:
        add(checks, "download.http", "L1", False, "descarga anónima falló", {"error": exc.__class__.__name__, "message": str(exc)[:300], "url": url})
    return False


def report_for(app: dict[str, Any], artifact: dict[str, Any], checks: list[Check]) -> dict[str, Any]:
    counts = {k: sum(1 for c in checks if c.status == k) for k in ("PASS", "FAIL", "SKIP")}
    return {
        "schema": "storeamo.verification.evidence.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "app_id": app.get("id"),
        "name": app.get("name"),
        "status": app.get("status"),
        "verified": False,
        "platform": artifact.get("platform"),
        "version": artifact.get("version"),
        "version_code": artifact.get("version_code"),
        "url": artifact.get("url"),
        "sha256": artifact.get("sha256"),
        "size_bytes": artifact.get("size_bytes"),
        "application_id": artifact.get("application_id"),
        "signing_cert_sha256": artifact.get("signing_cert_sha256"),
        "summary": {"ok": counts["FAIL"] == 0, "counts": counts},
        "checks": [asdict(c) for c in checks],
    }


def audit_downloads(catalog: dict[str, Any], out_dir: Path | None, checks: list[Check]) -> None:
    apps = catalog.get("apps", [])
    with tempfile.TemporaryDirectory(prefix="storeamo-verify-") as tmp:
        tmpdir = Path(tmp)
        for app in apps:
            if not isinstance(app, dict) or app.get("status") not in DOWNLOAD_STATUSES:
                continue
            for artifact in app.get("artifacts", []):
                if not isinstance(artifact, dict) or artifact.get("platform") != "android":
                    continue
                app_id = str(app.get("id"))
                version = str(artifact.get("version"))
                local_checks: list[Check] = []
                target = tmpdir / f"{app_id}-{version}.apk"
                url = str(artifact.get("url") or "")
                if download_artifact(url, target, local_checks):
                    verify_local_file(target, artifact, "android", local_checks)
                ok = not any(c.status == "FAIL" for c in local_checks)
                add(checks, f"audit.{app_id}", "L4", ok, f"auditoría binaria pública de {app_id}", {"version": version, "url": url})
                if out_dir is not None:
                    out_dir.mkdir(parents=True, exist_ok=True)
                    safe_version = re.sub(r"[^A-Za-z0-9._-]+", "-", version)
                    path = out_dir / f"{app_id}-v{safe_version}.json"
                    path.write_text(json.dumps(report_for(app, artifact, local_checks), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                for c in local_checks:
                    checks.append(Check(f"{app_id}.{c.id}", c.level, c.status, c.message, c.details))


def summary(checks: list[Check]) -> dict[str, Any]:
    counts = {k: sum(1 for c in checks if c.status == k) for k in ("PASS", "FAIL", "SKIP")}
    return {"ok": counts["FAIL"] == 0, "counts": counts}


def main() -> int:
    p = argparse.ArgumentParser(description="StoreAMO Verify")
    p.add_argument("catalog", type=Path)
    p.add_argument("--app")
    p.add_argument("--platform", choices=sorted(PLATFORMS))
    p.add_argument("--artifact", type=Path)
    p.add_argument("--audit-downloads", action="store_true", help="descarga y audita todos los APK candidate/verified")
    p.add_argument("--output-dir", type=Path, help="evidencia JSON por app para --audit-downloads")
    p.add_argument("--json", action="store_true")
    p.add_argument("--output", type=Path)
    args = p.parse_args()

    checks: list[Check] = []
    try:
        catalog = load_catalog(args.catalog)
    except Exception as exc:
        add(checks, "catalog.read", "L0", False, "no se pudo leer catálogo", {"error": exc.__class__.__name__})
        catalog = {}

    if catalog:
        validate_catalog(catalog, checks)
    if args.artifact:
        if not args.app or not args.platform:
            p.error("--artifact requiere --app y --platform")
        verify_artifact(catalog, args.app, args.platform, args.artifact, checks)
    if args.audit_downloads and catalog:
        audit_downloads(catalog, args.output_dir, checks)

    report = {
        "schema": "storeamo.verify.report.v2",
        "catalog": str(args.catalog),
        "app": args.app,
        "platform": args.platform,
        "artifact": str(args.artifact) if args.artifact else None,
        "audit_downloads": args.audit_downloads,
        "summary": summary(checks),
        "checks": [asdict(c) for c in checks],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    if args.json:
        print(text)
    else:
        for c in checks:
            print(f"{c.status:4} {c.level} {c.id}: {c.message}")
        s = report["summary"]
        print(f"\nRESULTADO: {'OK' if s['ok'] else 'FAIL'} · PASS={s['counts']['PASS']} FAIL={s['counts']['FAIL']} SKIP={s['counts']['SKIP']}")
    return 0 if report["summary"]["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
