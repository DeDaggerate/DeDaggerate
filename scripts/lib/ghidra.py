# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import os
import sys
from pathlib import Path

def get_ghidra_directory() -> Path:
	path = os.environ.get("GHIDRA_INSTALL_DIR")
	if path is None:
		sys.exit("error: $GHIDRA_INSTALL_DIR not set")

	directory = Path(path)
	if not (directory / "Ghidra").is_dir():
		sys.exit(f"error: {directory} doesn't look like a Ghidra install")

	return directory

def analyze_headless(ghidra_directory: Path) -> Path:
	for name in ("analyzeHeadless", "analyzeHeadless.bat"):
		candidate = ghidra_directory / "support" / name
		if candidate.is_file():
			return candidate

	sys.exit(f"error: analyzeHeadless not found under {ghidra_directory / 'support'}")
