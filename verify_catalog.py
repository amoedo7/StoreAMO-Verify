#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

SCHEMA = "storeamo.catalog.v1"
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
PLATFORMS = {"android", "windows", "macos", "linux", "web", "ios", "other"}
STATUSES = {"development", "candidate", "verified", "deprecated"}

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


def run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
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


def inspect_android(path: Path, artifact: dict[str, Any], checks: list[Check]) -> None:
    aapt = shutil.which("aapt2") or shutil.which("aapt")
    if aapt:
        code, out = run([aapt, "dump", "badging", str(path)])
        if code == 0:
            package_match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", out)
            details: dict[str, Any] = {}
            if package_match:
                package_name, version_code, version_name = package_match.groups()
                details.update(package_name=package_name, version_code=version_code, version_name=version_name)
                expected_package = artifact.get("application_id")
                if expected_package:
                    add(checks, "android.application-id", "L2", package_name == expected_package, "applicationId coincide", {"expected": expected_package, "found": package_name})
                else:
                    add(checks, "android.application-id", "L2", None, "catalogo no declara application_id", details)
                if artifact.get("version"):
                    add(checks, "android.version-name", "L2", version_name == str(artifact.get("version")), "versionName coincide", {"expected": artifact.get("version"), "found": version_name})
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
        expected_cert = str(artifact.get("signing_cert_sha256") or "").lower().replace(":", "")
        if code == 0 and expected_cert:
            found = None
            for line in out.splitlines():
                if "SHA-256 digest:" in line:
                    found = line.split("SHA-256 digest:", 1)[1].strip().lower().replace(":", "")
                    break
            add(checks, "android.signing-cert", "L3", found == expected_cert, "certificado coincide", {"expected": expected_cert, "found": found})
        elif not expected_cert:
            add(checks, "android.signing-cert", "L3", None, "catalogo no declara signing_cert_sha256")
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
        add(checks, "artifact.size", "L1", None, "catalogo no declara size_bytes")
    if platform == "android" or path.suffix.lower() == ".apk":
        inspect_android(path, artifact, checks)


def summary(checks: list[Check]) -> dict[str, Any]:
    counts = {k: sum(1 for c in checks if c.status == k) for k in ("PASS", "FAIL", "SKIP")}
    return {"ok": counts["FAIL"] == 0, "counts": counts}


def main() -> int:
    p = argparse.ArgumentParser(description="StoreAMO Verify")
    p.add_argument("catalog", type=Path)
    p.add_argument("--app")
    p.add_argument("--platform", choices=sorted(PLATFORMS))
    p.add_argument("--artifact", type=Path)
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

    report = {
        "schema": "storeamo.verify.report.v1",
        "catalog": str(args.catalog),
        "app": args.app,
        "platform": args.platform,
        "artifact": str(args.artifact) if args.artifact else None,
        "summary": summary(checks),
        "checks": [asdict(c) for c in checks],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
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
