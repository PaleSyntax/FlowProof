import importlib.util
from pathlib import Path


def _load_checker():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "check_version_consistency.py"
    spec = importlib.util.spec_from_file_location("check_version_consistency", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("version consistency checker could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_version_declarations_remain_consistent() -> None:
    checker = _load_checker()
    assert checker.find_mismatches(checker.collect_versions()) == []
