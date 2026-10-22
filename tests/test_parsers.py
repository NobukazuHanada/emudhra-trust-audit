"""Lock file parsing: pinned versions are pinned, ranges stay ranges."""

from __future__ import annotations

from ca_trust_audit.project import parsers


def names(dependencies):
    return {(item.name, item.version) for item in dependencies}


def test_npm_lock_v3_packages() -> None:
    text = """
    {
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/@anthropic-ai/claude-code": {"version": "2.1.300"},
        "node_modules/left-pad": {"version": "1.3.0"}
      }
    }
    """
    parsed = parsers.parse_npm_lock(text, file="package-lock.json")
    assert ("@anthropic-ai/claude-code", "2.1.300") in names(parsed)
    assert all(item.kind == parsers.PINNED for item in parsed)
    assert all(item.ecosystem == "npm" for item in parsed)


def test_npm_lock_v1_nested_dependencies() -> None:
    text = """
    {
      "lockfileVersion": 1,
      "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}
      }
    }
    """
    assert names(parsers.parse_npm_lock(text)) == {("a", "1.0.0"), ("b", "2.0.0")}


def test_yarn_lock() -> None:
    text = """
"@scope/pkg@^1.2.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/..."

left-pad@^1.0.0, left-pad@~1.1.0:
  version "1.3.0"
"""
    assert names(parsers.parse_yarn_lock(text)) == {("@scope/pkg", "1.2.3"), ("left-pad", "1.3.0")}


def test_pnpm_lock() -> None:
    text = """
packages:

  /certifi/2026.10.19:
    resolution: {integrity: sha512-xxx}

  '/@scope/pkg@3.1.4':
    resolution: {integrity: sha512-yyy}
"""
    parsed = names(parsers.parse_pnpm_lock(text))
    assert ("certifi", "2026.10.19") in parsed
    assert ("@scope/pkg", "3.1.4") in parsed


def test_requirements_distinguishes_pins_from_ranges() -> None:
    text = "\n".join(
        [
            "# comment",
            "certifi==2026.10.19",
            "requests[socks] >= 2.31.0",
            "urllib3~=2.2",
            "-r other.txt",
            "flask==3.0.0 ; python_version >= '3.9'",
        ]
    )
    parsed = {item.name: item for item in parsers.parse_requirements(text, file="requirements.txt")}
    assert parsed["certifi"].kind == parsers.PINNED
    assert parsed["certifi"].version == "2026.10.19"
    assert parsed["requests"].kind == parsers.RANGE
    assert parsed["urllib3"].kind == parsers.RANGE
    assert parsed["flask"].version == "3.0.0"


def test_toml_lock_covers_cargo_and_poetry() -> None:
    text = """
[[package]]
name = "webpki-roots"
version = "1.0.5"

[[package]]
name = "rustls-webpki"
version = "0.103.16"
checksum = "abc"
"""
    parsed = names(parsers.parse_toml_lock(text, file="Cargo.lock"))
    assert parsed == {("webpki-roots", "1.0.5"), ("rustls-webpki", "0.103.16")}


def test_composer_and_pipfile_and_gemfile_and_mix() -> None:
    composer = '{"packages": [{"name": "composer/ca-bundle", "version": "1.5.0"}]}'
    assert names(parsers.parse_composer_lock(composer)) == {("composer/ca-bundle", "1.5.0")}

    pipfile = '{"default": {"certifi": {"version": "==2026.10.19"}}}'
    assert names(parsers.parse_pipfile_lock(pipfile)) == {("certifi", "2026.10.19")}

    gemfile = "GEM\n  specs:\n    rails (7.1.3)\n    rake (13.1.0)\n"
    assert names(parsers.parse_gemfile_lock(gemfile)) == {("rails", "7.1.3"), ("rake", "13.1.0")}

    mix = '%{\n  "castore": {:hex, :castore, "1.0.8", "abc", ...},\n}'
    assert names(parsers.parse_mix_lock(mix)) == {("castore", "1.0.8")}


def test_go_module_files() -> None:
    gosum = "golang.org/x/net v0.24.0 h1:abc=\ngolang.org/x/net v0.24.0/go.mod h1:def=\n"
    assert names(parsers.parse_gosum(gosum)) == {("golang.org/x/net", "0.24.0")}

    gomod = "module example.com/app\n\ngo 1.26.0\n\ntoolchain go1.26.10\n"
    parsed = {item.parser: item for item in parsers.parse_gomod(gomod)}
    assert parsed["go.mod toolchain"].version == "1.26.10"
    assert parsed["go.mod toolchain"].kind == parsers.PINNED
    assert parsed["go.mod go directive"].kind == parsers.RANGE


def test_package_json_ranges_and_engines() -> None:
    text = '{"dependencies": {"a": "^1.2.3", "b": "2.0.0"}, "engines": {"node": ">=22.0.0"}}'
    parsed = {item.name: item for item in parsers.parse_package_json(text)}
    assert parsed["a"].kind == parsers.RANGE
    assert parsed["b"].kind == parsers.PINNED
    assert parsed["node"].kind == parsers.RANGE


def test_version_files() -> None:
    assert names(parsers.parse_tool_versions("nodejs 22.23.4\npython 3.12.3\n")) == {
        ("node", "22.23.4"),
        ("python", "3.12.3"),
    }
    assert names(parsers.parse_plain_version("v22.23.4\n", name="node")) == {("node", "22.23.4")}
    assert parsers.parse_plain_version("22\n", name="node")[0].kind == parsers.RANGE


def test_unparseable_input_returns_nothing_rather_than_raising() -> None:
    assert parsers.parse_npm_lock("{not json") == []
    assert parsers.parse_composer_lock("<html>") == []
    assert parsers.parse("no-such-parser", "data") == []


def test_find_prefers_exact_name_and_ecosystem() -> None:
    dependencies = parsers.parse_requirements("certifi==2026.10.19\n")
    assert parsers.find(dependencies, "CERTIFI")[0].version == "2026.10.19"
    assert parsers.find(dependencies, "certifi", ecosystem="npm") == []
