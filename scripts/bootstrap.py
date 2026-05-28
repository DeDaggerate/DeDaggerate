#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>
import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from lib.ghidra import analyze_headless, get_ghidra_directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BINARIES = PROJECT_ROOT / "binaries"
GHIDRA = PROJECT_ROOT / "ghidra"
ANNOTATIONS = PROJECT_ROOT / "annotations"
SCRIPTS = GHIDRA / "scripts"
PROJECT_NAME = "DeDaggerate"
TARGETS = [
	{
		"binary": "DAGGER.EXE",
		"sha256": "74d0216997e5fb5839d968a78855b94c5788dce61ca29df488d753d4a7477e8e",
		"loader": "MzLoader",
		"processor": "x86:LE:16:Real Mode",
		"cspec": "watcom16"
	},
	{
		"binary": "FALL.EXE",
		"sha256": "0c89487dc2e08f5a811c548d509d873fc7c868c6ab5b191cdca087ccff4c1bea",
		"loader": "LeLoader",
		"processor": "x86:LE:32:default",
		"cspec": "watcom"
	}
]

def sha256(path: Path) -> str:
	hashed = hashlib.sha256()
	with path.open("rb") as stream:
		for chunk in iter(lambda: stream.read(1 << 20), b""):
			hashed.update(chunk)

	return hashed.hexdigest()

def verify_binary(target: dict) -> Path | None:
	path = BINARIES / target["binary"]
	if not path.is_file():
		message = f"[bootstrap] missing {path} (you must supply your own copy)"
		if target.get("optional"):
			print(message + " — skipping")
			return None

		sys.exit(message)

	actual = sha256(path)
	if actual != target["sha256"]:
		print(f"[bootstrap] WARN: {target['binary']} SHA256 mismatch")
		print(f"\texpected {target['sha256']}")
		print(f"\tactual {actual}")
		print("\tannotations were captured against the expected hash; replay may misalign")

	return path

def nuke_project():
	for entry in GHIDRA.glob(f"{PROJECT_NAME}.*"):
		if entry.is_dir(): shutil.rmtree(entry)
		else: entry.unlink()

def import_target(analyze: Path, target: dict, binary_path: Path) -> bool:
	annotations_path = ANNOTATIONS / f"{target['binary']}.json"

	arguments = [
		str(analyze),
		str(GHIDRA),
		PROJECT_NAME,
		"-import", str(binary_path),
		"-loader", target["loader"],
		"-processor", target["processor"],
		"-cspec", target["cspec"],
		"-scriptPath", str(SCRIPTS),
	]

	if annotations_path.is_file(): arguments += [ "-postScript", "ImportAnnotations.java", str(annotations_path) ]
	else: print(f"[bootstrap] no annotations at {annotations_path}, importing without replay")

	print(f"[bootstrap] importing {target['binary']}")

	result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
	if result.returncode != 0:
		if target.get("optional"):
			print(f"[bootstrap] {target['binary']} import failed (optional, continuing):")
			print(result.stdout)

			return False

		print(result.stdout)
		sys.exit(f"[bootstrap] {target['binary']} import failed")

	return True

ghidra_directory = get_ghidra_directory()
analyze = analyze_headless(ghidra_directory)
binaries = []

for target in TARGETS:
	path = verify_binary(target)
	if path is not None:
		binaries.append((target, path))

if not binaries:
	sys.exit("[bootstrap] no binaries to import")

nuke_project()

GHIDRA.mkdir(parents=True, exist_ok=True)

imported = 0
for target, path in binaries:
	if import_target(analyze, target, path):
		imported += 1

print(f"[bootstrap] done: {imported}/{len(TARGETS)} imported into {GHIDRA / (PROJECT_NAME + '.gpr')}")
