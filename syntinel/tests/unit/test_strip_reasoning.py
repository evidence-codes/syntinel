from syntinel.infrastructure.ai.client import strip_reasoning


def test_strip_reasoning_removes_think_block():
    raw = "<think>let me consider the code...</think>SEVERITY: NONE\n----\n"
    assert strip_reasoning(raw) == "SEVERITY: NONE\n----"


def test_strip_reasoning_noop_without_think_block():
    raw = "SEVERITY: NONE\n----"
    assert strip_reasoning(raw) == raw


def test_strip_reasoning_multiline_case_insensitive():
    raw = "<THINK>\nmulti\nline\n</THINK>\nresult"
    assert strip_reasoning(raw) == "result"
