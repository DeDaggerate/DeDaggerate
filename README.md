# DeDaggerate

Reverse-engineering of Bethesda's 1996 *The Elder Scrolls II: Daggerfall*,
targeting the original Watcom 10-ish DOS build.

The game ships as two binaries:
- `DAGGER.EXE` — 16-bit launcher program
- `FALL.EXE` — 32-bit LE game/engine binary

The goal of this project is to produce a codebase that can _behaviourally_
replicate these programs in order to open up opportunities for porting and
other projects that benefit from access to a source tree.

This project does _not_ intend to produce a byte-for-byte decompilation.

## Ghidra

Scripts in this section expect you to have `$GHIDRA_INSTALL_DIR` set to point
at your Ghidra install.

### Setup

Install the required Ghidra extensions:
- [`ghidra-watcom-dos`](https://github.com/DeDaggerate/ghidra-watcom-dos)
provides Watcom compiler/libc support
- [`yetmorecode/ghidra-lx-loader`](https://github.com/yetmorecode/ghidra-lx-loader)
provides LE/LX executable loader

Drop your own copies of `DAGGER.EXE` and `FALL.EXE` into `binaries/`.
Daggerfall has been free for a few years now so it should be easy enough to
get your hands on a copy.

Then run `scripts/bootstrap.py` which will replay all annotations into a Ghidra
project. Then open the generated `ghidra/DeDaggerate.gpr` in Ghidra.

### Generating Annotations

To commit work you've done, export it with `scripts/export.py`. This overwrites
`annotations/DAGGER.EXE.json` and `annotations/FALL.EXE.json` with the current
user-defined markup.
