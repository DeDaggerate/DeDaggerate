#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import subprocess
import sys
from pathlib import Path

from lib.ghidra import analyze_headless, get_ghidra_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GHIDRA = PROJECT_ROOT / "ghidra"
SCRIPTS = GHIDRA / "scripts"
PROJECT_NAME = "DeDaggerate"

TARGETS = {
	"DAGGER.EXE": ("dagger/generated", "dagger", "dagger_*"),
	"FALL.EXE": ("fall/generated",   "fall",   "fall_*"),
}

def export_program(analyze: Path, program: str) -> bool:
	if program not in TARGETS:
		print(f"[export-sources] {program} not in TARGETS; skipping")
		return True

	out_directory_relative, basename, include = TARGETS[program]
	out_directory = PROJECT_ROOT / out_directory_relative
	out_directory.mkdir(parents=True, exist_ok=True)

	print(f"[export-sources] {program} -> {out_directory}/{basename}.{{c,asm,h}} (include={include!r})")

	arguments = [
		str(analyze), str(GHIDRA), PROJECT_NAME,
		"-process", program,
		"-noanalysis",
		"-readOnly",
		"-scriptPath", str(SCRIPTS),
		"-postScript", "ExportSources.java", str(out_directory), basename, include,
	]

	result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
	if result.returncode != 0:
		print(result.stdout)
		print(f"[export-sources] {program} failed")
		return False

	return True

ghidra_directory = get_ghidra_directory()
analyze = analyze_headless(ghidra_directory)

failed = 0
programs = sys.argv[1:] or list(TARGETS.keys())
for program in programs:
	if not export_program(analyze, program):
		failed += 1

if failed:
	sys.exit(f"[export-sources] {failed} program(s) failed")

print(f"[export-sources] done: {len(programs)} program(s)")
