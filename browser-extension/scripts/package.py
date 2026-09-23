"""Build the Chrome Web Store / Edge Add-ons upload zip.

    python scripts/package.py      (or: npm run package)

Only files the extension needs at runtime are included (no tests, scripts
or docs). The build fails if manifest.json points at a file that does not
exist, a common Web Store rejection.
"""

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = ["manifest.json", "background.js", "content.js", "popup.html", "popup.css", "popup.js"]


def referenced_files(manifest: dict) -> set[str]:
    files = {manifest["background"]["service_worker"], manifest["action"]["default_popup"]}
    files.update(manifest.get("icons", {}).values())
    files.update(manifest["action"].get("default_icon", {}).values())
    for script in manifest.get("content_scripts", []):
        files.update(script.get("js", []))
        files.update(script.get("css", []))
    return files


def main() -> int:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    files = sorted(set(RUNTIME_FILES) | referenced_files(manifest))
    missing = [name for name in files if not (ROOT / name).is_file()]
    if missing:
        print(f"manifest.json references missing files: {missing}", file=sys.stderr)
        return 1

    out_dir = ROOT / "dist"
    out_dir.mkdir(exist_ok=True)
    target = out_dir / f"secure-ai-prompt-gateway-{manifest['version']}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            archive.write(ROOT / name, name)
    print(f"{target.relative_to(ROOT)} ({len(files)} files, {target.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
