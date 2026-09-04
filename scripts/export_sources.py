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
SCRIPTS = GHIDRA / "scripts"
PROJECT_NAME = "DeDaggerate"

TARGETS = {
	"DAGGER.EXE": ("dagger/src", "dagger", "dagger_*"),
	"FALL.EXE": ("fall/src", "fall", "fall_*"),
}

MODE_ALL = "all"
MODE_C = "c"
MODE_ASM = "asm"

def export_program(analyze: Path, program: str, mode: str) -> bool:
	if program not in TARGETS:
		print(f"[export-sources] {program} not in TARGETS; skipping")
		return True

	out_directory_relative, basename, include = TARGETS[program]
	out_directory = PROJECT_ROOT / out_directory_relative
	out_directory.mkdir(parents=True, exist_ok=True)

	print(f"[export-sources] {program} -> {out_directory}/ (basename={basename}, include={include!r}, mode={mode})")

	arguments = [
		str(analyze), str(GHIDRA), PROJECT_NAME,
		"-process", program,
		"-noanalysis",
		"-readOnly",
		"-scriptPath", str(SCRIPTS),
		"-postScript", "ExportSources.java", str(out_directory), basename, include, mode,
	]

	result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
	if result.returncode != 0:
		print(result.stdout)
		print(f"[export-sources] {program} failed")
		return False

	return True

parser = argparse.ArgumentParser(description="Export decompiled C and/or asm sources from the Ghidra project.")
mode_group = parser.add_mutually_exclusive_group()
mode_group.add_argument("--asm-only", action="store_true", help="emit only the .asm file (skip .c and .h)")
mode_group.add_argument("--c-only", action="store_true", help="emit only the .c and .h files (skip .asm)")
parser.add_argument("programs", nargs="*", help="programs to export (default: all in TARGETS)")
args = parser.parse_args()

mode = MODE_ASM if args.asm_only else MODE_C if args.c_only else MODE_ALL

ghidra_directory = get_ghidra_directory()
analyze = analyze_headless(ghidra_directory)

failed = 0
programs = args.programs or list(TARGETS.keys())
for program in programs:
	if not export_program(analyze, program, mode):
		failed += 1

if failed:
	sys.exit(f"[export-sources] {failed} program(s) failed")

print(f"[export-sources] done: {len(programs)} program(s)")
