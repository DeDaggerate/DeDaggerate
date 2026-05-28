#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import argparse
import subprocess
import sys
from pathlib import Path

from lib.ghidra import analyze_headless, get_ghidra_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GHIDRA = PROJECT_ROOT / "ghidra"
ANNOTATIONS = PROJECT_ROOT / "annotations"
SCRIPTS = GHIDRA / "scripts"
PROJECT_NAME = "DeDaggerate"

PROGRAMS = ("DAGGER.EXE", "FALL.EXE")

def export_program(analyze: Path, program: str) -> bool:
	out_path = ANNOTATIONS / f"{program}.json"
	print(f"[export] {program} -> {out_path}")

	arguments = [
		str(analyze), str(GHIDRA), PROJECT_NAME,
		"-process", program,
		"-noanalysis",
		"-readOnly",
		"-scriptPath", str(SCRIPTS),
		"-postScript", "ExportAnnotations.java", str(out_path),
	]

	result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
	if result.returncode != 0:
		print(result.stdout)
		print(f"[export] {program} failed")
		return False

	return True

ghidra_directory = get_ghidra_directory()
analyze = analyze_headless(ghidra_directory)

ANNOTATIONS.mkdir(parents=True, exist_ok=True)

failed = 0
for program in sys.argv[1:]:
	if not export_program(analyze, program):
		failed += 1

if failed:
	sys.exit(f"[export] {failed} program(s) failed")

print(f"[export] done: {len(sys.argv[1:])} program(s)")
