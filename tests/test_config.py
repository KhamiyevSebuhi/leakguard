"""Configuration validation and bounded custom regexes."""

from pathlib import Path

import pytest

from leakguard.config import Config, custom_pattern, load_config
from leakguard.errors import ConfigError


def test_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config() == Config()
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing")


def test_valid(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('disabled_rules = ["jwt"]\nignore_paths = ["vendor/"]\nentropy_threshold = 4.8\nmax_file_size = 999\n[[custom_rules]]\nid="custom"\ndescription="Example"\npattern="ACME_[A-Z0-9]{20}"\nseverity="high"\n')
    result = load_config(path)
    assert result.disabled_rules == ("jwt",)
    assert result.ignore_paths == ("vendor/",)
    assert result.max_file_size == 999
    assert result.entropy_threshold == 4.8
    assert result.custom_rules[0].regex.fullmatch("ACME_" + "A1" * 10)


@pytest.mark.parametrize("text", ['[', 'unknown = 1', 'disabled_rules = "x"', 'disabled_rules = [1]', 'disabled_rules = ["missing"]', 'entropy_threshold = nan', 'entropy_threshold = true', 'entropy_threshold = 7', 'max_file_size = 0', 'max_file_size = true', 'custom_rules = 4', 'custom_rules = [4]', '[[custom_rules]]\nid="only"', '[[custom_rules]]\nid=3\ndescription="x"\npattern="a"\nseverity="HIGH"', '[[custom_rules]]\nid="jwt"\ndescription="x"\npattern="a"\nseverity="HIGH"', '[[custom_rules]]\nid="custom"\ndescription="x"\npattern="a"\nseverity="WRONG"'])
def test_invalid(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bad.toml"
    path.write_text(text)
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize("pattern", ["", "a" * 257, "(a+)+", "a*", "a{0}", "a{257}", "a{9,2}", "a{2}b{2}", "[z-a]"])
def test_unsafe_patterns(pattern: str) -> None:
    with pytest.raises(ConfigError):
        custom_pattern(pattern)


def test_bad_encoding_and_size(tmp_path: Path) -> None:
    path = tmp_path / "bad"
    for data in (b"\xff", b"a" * (1024 * 1024 + 1)):
        path.write_bytes(data)
        with pytest.raises(ConfigError):
            load_config(path)
