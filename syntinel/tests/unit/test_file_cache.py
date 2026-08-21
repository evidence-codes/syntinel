from syntinel.domain.models import FindingClass, ReviewFinding
from syntinel.infrastructure.cache.file_cache import FileCache, cache_key


def test_cache_key_is_stable_for_same_inputs():
    a = cache_key(content="x", prompt_version="v1", model="m")
    b = cache_key(content="x", prompt_version="v1", model="m")
    assert a == b


def test_cache_key_differs_on_prompt_version():
    a = cache_key(content="x", prompt_version="v1", model="m")
    b = cache_key(content="x", prompt_version="v2", model="m")
    assert a != b


def test_cache_round_trip(tmp_path):
    cache = FileCache(str(tmp_path))
    key = cache_key(content="x", prompt_version="v1", model="m")
    findings = [
        ReviewFinding(
            severity="HIGH",
            file_path="a.py",
            issue="bad thing",
            finding_class=FindingClass.LOGIC,
        )
    ]

    assert cache.get(key) is None
    cache.set(key, findings)
    restored = cache.get(key)

    assert restored is not None
    assert restored[0].file_path == "a.py"
    assert restored[0].finding_class == FindingClass.LOGIC
