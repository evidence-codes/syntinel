from itertools import pairwise

from syntinel.domain.scan_rules import chunk_file, is_reviewable_path


def test_is_reviewable_path_true_for_known_extensions():
    assert is_reviewable_path("src/app.py") is True
    assert is_reviewable_path("src/app.TS") is True


def test_is_reviewable_path_false_for_unknown_extensions():
    assert is_reviewable_path("README.md") is False
    assert is_reviewable_path("image.png") is False


def test_chunk_file_single_chunk_when_small():
    content = "a" * 50
    chunks = chunk_file("f.py", content, max_chars=100)
    assert len(chunks) == 1
    assert chunks[0].content == content
    assert chunks[0].start_line == 1


def test_chunk_file_splits_on_line_boundary_when_large():
    lines = [f"line{i}\n" for i in range(20)]
    content = "".join(lines)
    chunks = chunk_file("f.py", content, max_chars=40)
    assert len(chunks) > 1
    # Reassembling all chunk contents must reproduce the original file exactly.
    assert "".join(c.content for c in chunks) == content
    # Line ranges must be contiguous and non-overlapping.
    for prev, nxt in pairwise(chunks):
        assert nxt.start_line == prev.end_line + 1
