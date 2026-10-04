"""The verifier's generated-output cleanup must preserve the source staging tree."""
import pytest

from verify import clear_generated_build


def test_uppercase_build_and_sentinel_survive(tmp_path):
    staged = tmp_path / 'Build'
    staged.mkdir()
    sentinel = staged / 'source-sentinel'
    sentinel.write_bytes(b'keep staged inputs')
    lowercase = tmp_path / 'build'
    distinct_names = not lowercase.exists()
    if distinct_names:
        lowercase.mkdir()  # Case-sensitive CI can have both names at once.
        (lowercase / 'stale-artifact').write_bytes(b'old')
    else:
        assert lowercase.samefile(staged)  # Case-insensitive filesystem regression.

    clear_generated_build(tmp_path)

    assert sentinel.read_bytes() == b'keep staged inputs'
    assert staged.is_dir()
    if distinct_names:
        assert not lowercase.exists()


def test_real_lowercase_build_is_removed(tmp_path):
    generated = tmp_path / 'build'
    generated.mkdir()
    (generated / 'stale-artifact').write_bytes(b'old')

    clear_generated_build(tmp_path)

    assert not generated.exists()


def test_lowercase_build_symlink_is_rejected(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    sentinel = target / 'source-sentinel'
    sentinel.write_bytes(b'keep target')
    link = tmp_path / 'build'
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match='Refusing to remove symlink'):
        clear_generated_build(tmp_path)

    assert link.is_symlink()
    assert sentinel.read_bytes() == b'keep target'
