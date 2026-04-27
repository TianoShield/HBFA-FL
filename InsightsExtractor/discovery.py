# =============================================================================
# discovery.py — Scan HBFA TestCase/ for fuzz harnesses
# =============================================================================

"""Discover harnesses and map them to actual edk2 source paths.

Each harness INF lives at:
    HBFA/UefiHostFuzzTestCasePkg/TestCase/<edk2_rel_path>/<TestX>.inf

The directory structure mirrors edk2 layout, so for
``TestCase/SecurityPkg/Library/FmpAuthenticationLibPkcs7/TestX.inf``
the actual edk2 source under test is ``edk2/SecurityPkg/Library/FmpAuthenticationLibPkcs7/``.
"""

import re
from pathlib import Path

from .config import (
    AFL_OUTPUT_PREFIX,
    BUILD_AFL_DIR,
    BUILD_GCC5_DIR,
    HBFA_PKG_DIR,
    HBFA_PKG_NAME,
    SEED_ROOT,
    TESTCASE_ROOT,
)

# INF files to ignore — these are helper/override modules, not standalone harnesses
_INF_BLOCKLIST_SUBSTR = (
    "Override",
    "InstrumentHookLib",
    "StubLib",
    "CryptoLibStub",
)


# Harnesses whose TestCase/ directory name does not match the (set of) real
# edk2 source directories under test. Each value is a list of paths relative
# to edk2/. The first entry is the primary directory (used for display); all
# entries are passed to lcov --extract to scope the report.
_EDK2_REL_OVERRIDES = {
    # NOTE: every Virtio harness in HBFA links *stub* library classes
    # (VirtioBlkStubLib / VirtioPciDevice{,10}StubLib) instead of the real
    # edk2 OvmfPkg drivers, so the only real edk2 component their binary
    # actually executes is OvmfPkg/Library/VirtioLib (the shared queue
    # helper). Scoping to anything else will report 0/0 because no .gcda
    # is ever produced for code that isn't linked.
    "TestVirtioBlk": [
        "OvmfPkg/Library/VirtioLib",
    ],
    "TestVirtioBlkReadWrite": [
        "OvmfPkg/Library/VirtioLib",
    ],
    "TestVirtioPciDevice": [
        "OvmfPkg/Library/VirtioLib",
    ],
    "TestVirtio10Blk": [
        "OvmfPkg/Library/VirtioLib",
    ],
    # TCG2 measure-boot harnesses live under DxeTpm2MeasureBootLib but the
    # real GPT/PE parsing code lives in MdeModulePkg.
    "TestTcg2MeasureGptTable": [
        "SecurityPkg/Library/DxeTpm2MeasureBootLib",
        "MdeModulePkg/Universal/Disk/PartitionDxe",
    ],
    "TestTcg2MeasurePeImage": [
        "SecurityPkg/Library/DxeTpm2MeasureBootLib",
        "MdePkg/Library/BasePeCoffLib",
    ],
}


def _parse_base_name(inf_path: Path) -> str:
    for line in inf_path.read_text(errors="ignore").splitlines():
        m = re.match(r"\s*BASE_NAME\s*=\s*(\S+)", line)
        if m:
            return m.group(1).strip()
    return inf_path.stem


def _dsc_components() -> set:
    """INF paths (relative to HBFA_DIR) listed in the DSC's [Components] section.

    Harnesses not registered in the DSC cannot be built (`build` will reject
    them with "Module ... is not a component of active platform"), so they
    must be excluded from discovery even if a TestX.inf exists under TestCase/.
    """
    dsc = HBFA_PKG_DIR / f"{HBFA_PKG_NAME}.dsc"
    components = set()
    in_components = False
    for raw in dsc.read_text(errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            in_components = line.lower().startswith("[components")
            continue
        if not in_components:
            continue
        m = re.search(r"([A-Za-z0-9_./-]+\.inf)", line)
        if m:
            components.add(m.group(1))
    return components


def _is_harness_inf(inf_path: Path) -> bool:
    name = inf_path.name
    if not name.startswith("Test"):
        return False
    rel = str(inf_path.relative_to(TESTCASE_ROOT))
    if any(bad in rel for bad in _INF_BLOCKLIST_SUBSTR):
        return False
    return True


def discover_harnesses() -> dict:
    """Return ``{harness_name: info_dict}`` for every fuzz harness under TestCase/.

    Only harnesses registered in ``UefiHostFuzzTestCasePkg.dsc`` ``[Components]``
    are returned, since unlisted INFs cannot be built by the platform.

    info_dict keys:
        inf_abs        Path to the .inf file
        inf_rel        Path string relative to HBFA_DIR (used by `build -m`)
        edk2_rel       edk2-relative source dir (e.g. "SecurityPkg/Library/FmpAuthenticationLibPkcs7")
        binary_afl     Path to AFL-instrumented binary
        binary_gcc5    Path to coverage binary
        afl_output     <AFL_OUTPUT_PREFIX><name>  (default /tmp/afl_out_<name>)
        seed_dir       Best-guess seed directory
    """
    components = _dsc_components()
    registry = {}
    for inf in sorted(TESTCASE_ROOT.rglob("Test*.inf")):
        if not _is_harness_inf(inf):
            continue
        inf_rel = str(inf.relative_to(HBFA_PKG_DIR.parent))
        if inf_rel not in components:
            continue
        name = _parse_base_name(inf)
        override = _EDK2_REL_OVERRIDES.get(name)
        if override:
            edk2_rels = list(override)
        else:
            edk2_rels = [str(inf.parent.relative_to(TESTCASE_ROOT))]
        registry[name] = {
            "inf_abs":     inf,
            "inf_rel":     inf_rel,
            "edk2_rel":    edk2_rels[0],   # primary, used for display/CSV
            "edk2_rels":   edk2_rels,      # full list, used for lcov scoping
            "binary_afl":  BUILD_AFL_DIR / name,
            "binary_gcc5": BUILD_GCC5_DIR / name,
            "afl_output":  Path(f"{AFL_OUTPUT_PREFIX}{name}"),
            "seed_dir":    _guess_seed_dir(name),
        }
    return registry


# Authoritative seed-dir mapping from
# docs/src/harness/includedfuzzharnesses.md — the HBFA tree nests seed
# inputs under per-domain folders that don't match the harness name.
_SEED_MAP = {
    "TestTpm2CommandLib":                    "TPM/Raw",
    "TestBmpSupportLib":                     "BMP/Raw",
    "TestPartition":                         "UDF/Raw/Partition",
    "TestUdf":                               "UDF/Raw/FileSystem",
    "TestFileName":                          "UDF/Raw/FileName",
    "TestPeiUsb":                            "USB/Raw",
    "TestUsb":                               "USB/Raw",
    "TestIdentifyAtaDevice":                 "Ata/Raw",
    "TestPeiGpt":                            "Gpt/Raw",
    "TestSignatureList":                     "SignatureList/Raw",
    "TestVariableSmm":                       "VariableSmm/Raw",
    "TestCapsulePei":                        "Capsule",
    "TestFmpAuthenticationLibPkcs7":         "Capsule",
    "TestFmpAuthenticationLibRsa2048Sha256": "Capsule",
    "TestTcg2MeasureGptTable":               "Gpt/Raw",
    "TestTcg2MeasurePeImage":                "Capsule",
    "TestValidateTdxCfv":                    "TdxHob/Raw",
    "TestVirtioPciDevice":                   "Blk",
    "TestVirtio10Blk":                       "Blk",
    "TestVirtioBlk":                         "Blk",
    "TestVirtioBlkReadWrite":                "Blk",
}


def _guess_seed_dir(name: str) -> Path:
    """Resolve a harness seed directory.

    Uses the documented mapping first, then falls back to Seed/<name>/
    or Seed/<name without leading 'Test'>/ for harnesses not in the
    table (e.g. user-added cases).
    """
    sub = _SEED_MAP.get(name)
    if sub:
        p = SEED_ROOT / sub
        if p.is_dir():
            return p
    for c in (SEED_ROOT / name, SEED_ROOT / name.removeprefix("Test")):
        if c.is_dir() and any(c.iterdir()):
            return c
    return SEED_ROOT / name
