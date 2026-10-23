#!/usr/bin/env bash
# Maintainer/CI checks for the two skills-only plugins. Users never run this.
# Usage: bash scripts/validate.sh [static|posix|windows|all]
# Needs bash, jq, awk, grep, sed, openssl (and powershell.exe for "windows").
set -eu
export LC_ALL=C

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
PLUGINS="endpoint-trust-audit project-trust-audit"
SE=plugins/endpoint-trust-audit/skills/endpoint-trust-audit
SP=plugins/project-trust-audit/skills/project-trust-audit
MODE=${1:-all}
FAILS=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }
ok() { printf 'ok: %s\n' "$*"; }

# Print the body of the fenced block that follows the marker comment NAME.
block_after_marker() { # file marker lang
  awk -v m="<!-- $2: begin -->" -v lang="$3" '
    $0 == m { armed = 1; next }
    armed && $0 == "```" lang { inb = 1; next }
    inb && $0 == "```" { exit }
    inb { print }' "$1"
}
# Print the Nth fenced block of the given language (1-based).
nth_block() { # file lang n
  awk -v lang="$2" -v want="$3" '
    $0 == "```" lang { n++; inb = (n == want); next }
    inb && $0 == "```" { exit }
    inb { print }' "$1"
}
ioc_set() { grep -oE '[0-9A-F]{64}' "$1" | sort -u; }

static_checks() {
  # Manifests: one plugin per skill, listed in both marketplaces in the same order.
  local cm=.claude-plugin/marketplace.json xm=.agents/plugins/marketplace.json
  for f in $cm $xm; do jq empty "$f" 2>/dev/null && ok "json $f" || fail "invalid JSON $f"; done
  [ "$(jq -r '[.plugins[].name] | join(" ")' $cm)" = "$PLUGINS" ] || fail "claude marketplace plugin list"
  [ "$(jq -r '[.plugins[].name] | join(" ")' $xm)" = "$PLUGINS" ] || fail "codex marketplace plugin list"
  local pl v0="" n1 n2 v1 v2
  for pl in $PLUGINS; do
    local P=plugins/$pl
    for f in "$P/.claude-plugin/plugin.json" "$P/.codex-plugin/plugin.json"; do
      jq empty "$f" 2>/dev/null && ok "json $f" || fail "invalid JSON $f"
    done
    n1=$(jq -r .name "$P/.claude-plugin/plugin.json")
    n2=$(jq -r .name "$P/.codex-plugin/plugin.json")
    v1=$(jq -r .version "$P/.claude-plugin/plugin.json")
    v2=$(jq -r .version "$P/.codex-plugin/plugin.json")
    [ "$n1" = "$pl" ] && [ "$n2" = "$pl" ] || fail "$pl: manifest names $n1 $n2"
    [ "$v1" = "$v2" ] || fail "$pl: versions differ: $v1 $v2"
    [ -z "$v0" ] || [ "$v1" = "$v0" ] || fail "plugins have different versions: $v0 $v1"
    v0=$v1
    [ "$(jq -r .skills "$P/.codex-plugin/plugin.json")" = ./skills/ ] || fail "$pl: codex skills path"
    for k in displayName shortDescription longDescription developerName category; do
      [ -n "$(jq -r ".interface.$k // empty" "$P/.codex-plugin/plugin.json")" ] || fail "$pl: codex interface.$k missing"
    done
    [ "$(jq -r '.interface.shortDescription | length' "$P/.codex-plugin/plugin.json")" -le 30 ] || fail "$pl: shortDescription over 30 chars"
    for k in logo composerIcon; do
      p=$(jq -r ".interface.$k" "$P/.codex-plugin/plugin.json")
      [ -f "$P/$p" ] || fail "$pl: codex interface.$k file missing: $p"
    done
    [ "$(jq -r --arg n "$pl" '.plugins[] | select(.name == $n) | .source' $cm)" = "./$P" ] || fail "$pl: claude marketplace source"
    [ "$(jq -r --arg n "$pl" '.plugins[] | select(.name == $n) | .source.path' $xm)" = "./$P" ] || fail "$pl: codex marketplace source"
    for k in policy.installation policy.authentication category; do
      [ -n "$(jq -r --arg n "$pl" ".plugins[] | select(.name == \$n) | .$k // empty" $xm)" ] || fail "$pl: codex marketplace $k missing"
    done
    [ "$(find "$P/skills" -mindepth 1 -maxdepth 1 -type d)" = "$P/skills/$pl" ] || fail "$pl: must contain exactly the skill $pl"
  done
  grep -q "^## $v0 " CHANGELOG.md || fail "CHANGELOG has no entry for $v0"
  ok "manifests consistent (version $v0)"

  # Repository hygiene
  if [ -n "$(find . -path ./.git -prune -o -type l -print)" ]; then fail "symbolic links present"; fi
  if [ -n "$(find . -path ./.git -prune -o -type f -size +256k -print)" ]; then fail "file over 256 KiB"; fi
  if [ -n "$(find . -path ./.git -prune -o \( -name .DS_Store -o -name Thumbs.db -o -name '*.py' -o -name '*.rs' -o -name Cargo.toml -o -name '*.exe' -o -name '*.zip' \) -print)" ]; then fail "forbidden file type present"; fi
  for pl in $PLUGINS; do
    bad=$(find "plugins/$pl" -type f ! -name '*.md' ! -name '*.json' ! -name '*.svg' ! -name LICENSE ! -name NOTICE)
    [ -z "$bad" ] || fail "non-text file in plugin: $bad"
    [ "$(find "plugins/$pl" -type f | wc -l)" -lt 512 ] || fail "too many files in $pl"
    cmp -s LICENSE "plugins/$pl/LICENSE" || fail "$pl LICENSE differs from root"
    cmp -s NOTICE "plugins/$pl/NOTICE" || fail "$pl NOTICE differs from root"
    [ "$(wc -w < "plugins/$pl/README.md")" -ge 40 ] || fail "$pl README under 40 words"
  done
  [ "$(find plugins -mindepth 1 -maxdepth 1 -type d | sort | sed 's#^plugins/##' | tr '\n' ' ')" = "$PLUGINS " ] || fail "unexpected directories in plugins/"
  grep -q 'Apache License' LICENSE || fail "LICENSE is not Apache-2.0"
  ok "repository hygiene"

  # Skills
  local s d name desc
  for d in $SE $SP; do
    s=${d##*/}
    f="$d/SKILL.md"
    [ -f "$f" ] || { fail "$s: SKILL.md missing"; continue; }
    [ "$(head -n 1 "$f")" = --- ] || fail "$s: frontmatter missing"
    name=$(awk 'NR > 1 && /^---$/ { exit } NR > 1 && /^name: / { sub(/^name: /, ""); print }' "$f")
    desc=$(awk 'NR > 1 && /^---$/ { exit } NR > 1 && /^description: / { sub(/^description: /, ""); print }' "$f")
    [ "$name" = "$s" ] || fail "$s: name '$name' differs from folder"
    printf '%s' "$name" | grep -qE '^[a-z0-9]+(-[a-z0-9]+)*$' && [ ${#name} -le 64 ] || fail "$s: name format"
    [ -n "$desc" ] && [ ${#desc} -le 1024 ] || fail "$s: description empty or over 1024 chars (${#desc})"
    [ "$(wc -l < "$f")" -lt 500 ] || fail "$s: SKILL.md has 500+ lines"
    for h in '## Safety rules' '## Workflow' '## Classification' '## Report' '## Limitations'; do
      grep -qx "$h" "$f" || fail "$s: heading '$h' missing"
    done
    for r in $(grep -oE 'references/[A-Za-z0-9._-]+' "$f" | sort -u); do
      [ -f "$d/$r" ] || fail "$s: broken reference $r"
    done
    for r in "$d"/references/*.md; do
      grep -q "references/${r##*/}" "$f" || fail "$s: ${r##*/} not referenced from SKILL.md"
    done
    for st in known_indicator suspicious not_found unable_to_assess; do
      grep -q "$st" "$f" || fail "$s: status $st not described"
    done
    grep -qi 'not affiliated' "$f" || fail "$s: affiliation disclaimer missing"
    grep -q 'Not detected does not mean safe' "$f" || fail "$s: not-safe statement missing"
    ok "skill $s"
  done
  for r in indicators.md fixed-versions.md report-template.md; do
    cmp -s "$SE/references/$r" "$SP/references/$r" \
      || fail "shared file $r differs between skills"
  done

  # Indicator data: provenance and identical hash sets everywhere
  local ind="$SE/references/indicators.md"
  for k in 'Data version' 'Facts as of' 'Sources retrieved' '## Sources'; do
    grep -q "$k" "$ind" || fail "indicators.md lacks '$k'"
  done
  ioc_set "$ind" > "$TMP/ioc"
  [ "$(wc -l < "$TMP/ioc")" -eq 8 ] || fail "expected 8 indicators"
  for f in $SE/references/commands-*.md $SP/references/commands-*.md; do
    ioc_set "$f" > "$TMP/ioc2"
    cmp -s "$TMP/ioc" "$TMP/ioc2" || fail "indicator hashes in $f differ from indicators.md"
  done
  # The POSIX SPKI filter (from "| awk -v h=" onward) and the Windows hash function must be identical.
  for s in endpoint project; do
    d=$SE; [ $s = project ] && d=$SP
    block_after_marker "$d/references/commands-posix.md" spki-filter sh \
      | sed -n '/awk -v h=/,$p' | sed '1s/.*| awk -v h=/awk -v h=/' > "$TMP/filter-$s"
    awk '/^function Get-P384SpkiSha256/,/^}/' "$d/references/commands-windows.md" > "$TMP/winfn-$s"
  done
  cmp -s "$TMP/filter-endpoint" "$TMP/filter-project" || fail "SPKI filters differ between skills"
  cmp -s "$TMP/winfn-endpoint" "$TMP/winfn-project" || fail "Windows SPKI functions differ between skills"
  [ -s "$TMP/filter-endpoint" ] && [ -s "$TMP/winfn-endpoint" ] || fail "SPKI filter or Windows function not found"
  ok "indicator data consistent"

  # TLS rules: every documented pattern is in the POSIX and Windows catalogues
  local rules="$SP/references/tls-rules.md"
  local px="$SP/references/commands-posix.md"
  local pw="$SP/references/commands-windows.md"
  block_after_marker "$px" tls-grep sh | sed -n "s/^ *-e '\(.*\)' \\\\\$/\1/p" | sed "s/'\\\\''/'/g" | sort > "$TMP/px-patterns"
  sed -n 's/^- Pattern: `\(.*\)`$/\1/p' "$rules" | sort > "$TMP/rule-patterns"
  [ "$(wc -l < "$TMP/rule-patterns")" -eq 19 ] || fail "expected 19 TLS rules"
  cmp -s "$TMP/rule-patterns" "$TMP/px-patterns" || { fail "tls-rules.md patterns differ from P2 block"; diff "$TMP/rule-patterns" "$TMP/px-patterns" || true; }
  while IFS= read -r p; do
    w=$(printf '%s' "$p" | sed 's/\[\[:space:\]\]/\\s/g; s/\[:space:\]/\\s/g; '"s/'/''/g")
    grep -qF "'$w'" "$pw" || fail "Windows catalogue lacks rule pattern: $p"
  done < "$TMP/rule-patterns"
  ok "TLS rules consistent"

  # Catalogue blocks may only call allowlisted, read-only commands.
  local sh_allow=' export uname grep find awk cat printf echo command printenv sh [ continue head dpkg-query rpm pacman apk /usr/bin/security /usr/bin/sw_vers fi done esac '
  local ps_cmd_allow=' Get-ChildItem Get-Item Get-ItemProperty Test-Path Join-Path Select-String Select-Object Where-Object ForEach-Object New-Object Get-Location Get-P384SpkiSha256 Read-PemCertificates Test-Certificates Test-LocalFile '
  local ps_static_allow=' ReadAllText OpenRead GetEnvironmentVariable OSVersion ToString FromBase64String Matches Create Min IndexOf ReparsePoint '
  local ps_method_allow=' GetFileSystemInfos Push Pop Add Read Dispose ComputeHash Replace Substring TrimEnd TrimStart Split ContainsKey ToString '
  local filter_cmd="-v h='openssl x509 -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null'"
  local inner="sh -c 'for f do printf \"FILE\\tLABEL\\n\"; cat -- \"\$f\"; done' sh"
  for f in $SE/references/commands-*.md $SP/references/commands-*.md; do
    for lang in sh powershell; do
      i=1
      while :; do
        nth_block "$f" "$lang" "$i" > "$TMP/blk"
        [ -s "$TMP/blk" ] || break
        where="$f ($lang block $i)"
        grep -qE 'system\(|getline|ExecutionPolicy|Invoke-|iex |Start-Process|Out-File|Set-Content|Add-Content|Remove-Item' "$TMP/blk" \
          && fail "forbidden construct in $where"
        # An awk program may pipe only to the canonical command "h"; grep patterns (-e lines) may contain |".
        grep -vE "^ *(-e '|grep )" "$TMP/blk" | grep -qE '\| *"' && [ "$lang" = sh ] && fail "awk pipe to a literal command in $where"
        if [ "$lang" = sh ]; then
          grep -o "sh -c '[^']*' sh" "$TMP/blk" | sed -e 's/FILE\\t[^"]*\\n" "\$f";/FILE\\tLABEL\\n";/' -e 's/FILE\\t[^"]*\\n";/FILE\\tLABEL\\n";/' | sort -u > "$TMP/inner"
          [ ! -s "$TMP/inner" ] || [ "$(cat "$TMP/inner")" = "$inner" ] || { fail "unexpected sh -c script in $where"; cat "$TMP/inner" >&2; }
          grep -o "\-v h='[^']*'" "$TMP/blk" | sort -u > "$TMP/hcmd"
          [ ! -s "$TMP/hcmd" ] || [ "$(cat "$TMP/hcmd")" = "$filter_cmd" ] || fail "unexpected awk pipe command in $where"
          grep -oE '/usr/bin/security [a-z-]+' "$TMP/blk" | grep -vE ' (find-certificate|dump-trust-settings)$' && fail "security subcommand in $where"
          # Strip quoted text, join continuations, drop allowed redirections, then check every command word.
          awk '{ s = s $0 "\n" } END { st = 0; out = ""
            for (i = 1; i <= length(s); i++) { c = substr(s, i, 1)
              if (st == 0) { if (c == "\047") { st = 1; out = out "Q" } else if (c == "\"") { st = 2; out = out "Q" } else if (c == "\\") { out = out c substr(s, i + 1, 1); i++ } else out = out c }
              else if (st == 1) { if (c == "\047") st = 0 }
              else { if (c == "\\") i++; else if (c == "\"") st = 0 } }
            printf "%s", out }' "$TMP/blk" \
            | sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' \
            | sed -e 's#2>/dev/null##g; s#>/dev/null##g; s#2>&1##g; s#\\(#LP#g; s#\\)#RP#g; s#{}#BR#g' > "$TMP/code"
          grep -n '>' "$TMP/code" && fail "redirection in $where"
          tr ';|&(){}' '\n\n\n\n\n\n\n' < "$TMP/code" | while read -r w rest; do
            while :; do case "$w" in if|then|else|elif|do|while|until|'!') set -- $rest; w=${1:-}; shift || true; rest="$*" ;; *) break ;; esac; done
            case "$w" in ''|for|case|'$'|*=*) continue ;; esac
            case "$sh_allow" in *" $w "*) ;; *) echo "command '$w'" ;; esac
          done > "$TMP/badcmd"
          [ -s "$TMP/badcmd" ] && { fail "non-allowlisted command in $where"; sort -u "$TMP/badcmd" >&2; }
        else
          sed "s/'[^']*'/Q/g" "$TMP/blk" > "$TMP/code"
          grep -oE '\b[A-Z][a-z]+-[A-Z][A-Za-z0-9]+\b' "$TMP/code" | sort -u | while read -r w; do
            case "$ps_cmd_allow" in *" $w "*) ;; *) echo "cmdlet $w" ;; esac
          done > "$TMP/badcmd"
          grep -oE '::[A-Za-z0-9]+' "$TMP/code" | sed 's/:://' | sort -u | while read -r w; do
            case "$ps_static_allow" in *" $w "*) ;; *) echo "static $w" ;; esac
          done >> "$TMP/badcmd"
          grep -oE '\.[A-Za-z]+\(' "$TMP/code" | sed 's/^\.//; s/($//' | sort -u | while read -r w; do
            case "$ps_method_allow" in *" $w "*) ;; *) echo "method $w" ;; esac
          done >> "$TMP/badcmd"
          grep -nE '(^|[^-])>|&[^ {]|& *[^{]' "$TMP/code" | grep -v '^1:& {$' >> "$TMP/badcmd" || true
          [ -s "$TMP/badcmd" ] && { fail "non-allowlisted PowerShell in $where"; cat "$TMP/badcmd" >&2; }
        fi
        i=$((i + 1))
      done
    done
  done
  ok "catalogue blocks use only allowlisted read-only commands"

  # Markdown links in top-level docs
  for f in README.md README.ja.md CONTRIBUTING.md SECURITY.md PRIVACY.md CHANGELOG.md AGENTS.md plugins/*/README.md; do
    for l in $(grep -oE '\]\([^)#]+\)' "$f" | sed 's/^](//; s/)$//' | grep -vE '^(https?|mailto):'); do
      [ -e "$(dirname "$f")/$l" ] || fail "$f: broken link $l"
    done
  done

  # README parity
  local en=README.md ja=README.ja.md
  [ "$(head -n 1 "$en")" = '[English](README.md) | [日本語](README.ja.md)' ] || fail "README.md cross-link line"
  [ "$(head -n 1 "$ja")" = '[English](README.md) | [日本語](README.ja.md)' ] || fail "README.ja.md cross-link line"
  [ "$(grep -c '^## ' "$en")" -eq "$(grep -c '^## ' "$ja")" ] || fail "README section counts differ"
  [ "$(grep -c '^### ' "$en")" -eq "$(grep -c '^### ' "$ja")" ] || fail "README subsection counts differ"
  for i in 1 2 3; do
    cmp -s <(nth_block "$en" sh "$i") <(nth_block "$ja" sh "$i") || fail "README sh block $i differs"
  done
  grep -oE '`(claude|codex|/plugin) [^`]+`' "$en" | sort -u > "$TMP/cmd-en"
  grep -oE '`(claude|codex|/plugin) [^`]+`' "$ja" | sort -u > "$TMP/cmd-ja"
  cmp -s "$TMP/cmd-en" "$TMP/cmd-ja" || fail "README inline commands differ"
  for k in archive/rust-cli 3233891a5578630200f95ccbd74577553e2b4845 Apache-2.0 PRIVACY.md \
    endpoint-trust-audit project-trust-audit known_indicator suspicious not_found unable_to_assess \
    2026-10-21 2026.10.22 .claude-plugin/marketplace.json .agents/plugins/marketplace.json; do
    grep -qF "$k" "$en" || fail "README.md lacks $k"
    grep -qF "$k" "$ja" || fail "README.ja.md lacks $k"
  done
  grep -q 'Not affiliated' "$en" || fail "README.md lacks disclaimer"
  grep -q '提携しておらず' "$ja" || fail "README.ja.md lacks disclaimer"
  ok "README parity"
}

make_fixture() { # dir -> prints synthetic SPKI hash
  local dir=$1
  mkdir -p "$dir/proj/certs" "$dir/proj/node_modules/x"
  # Relative paths: native Windows openssl builds cannot open MSYS-style /tmp paths.
  (cd "$dir" && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout key.pem \
    -out proj/certs/ca-bundle.pem -subj /CN=synthetic-test -days 1 >/dev/null 2>&1)
  printf 'not a certificate\n' > "$dir/proj/certs/junk.crt"
  sed -n 's/^- Example: `\(.*\)`$/\1/p' "$SP/references/tls-rules.md" > "$dir/proj/app.sh"
  printf 'registry=http://localhost:4873\n' >> "$dir/proj/app.sh"
  printf 'strict-ssl=false\n' > "$dir/proj/node_modules/x/.npmrc"
  printf '[[package]]\nname = "certifi"\nversion = "2026.10.1"\n' > "$dir/proj/uv.lock"
  printf 'go 1.26.4\n' > "$dir/proj/go.mod"
  printf 'FROM node:22.1\nRUN TOKEN=s3cr3t-docker update-ca-certificates\n' > "$dir/proj/Dockerfile"
  printf 'index-url = http://alice:s3cr3t-url@pypi.example.invalid/simple\n' > "$dir/proj/pip.conf"
  printf '[env]\nAPI_KEY = "s3cr3t-1234"\n[tools]\nnode = "22.1.0"\n' > "$dir/proj/mise.toml"
  printf '{\n  "packages": {\n    "node_modules/electron": {\n      "version": "30.0.0",\n      "resolved": "https://bob:s3cr3t-npm@registry.example.invalid/electron.tgz"\n    }\n  }\n}\n' > "$dir/proj/package-lock.json"
  (cd "$dir" && openssl x509 -in proj/certs/ca-bundle.pem -noout -pubkey | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256) | tr -d '\r' | awk '{ print toupper($NF) }'
}

posix_checks() {
  local E="$SE/references/commands-posix.md"
  local P="$SP/references/commands-posix.md"
  local first; first=$(head -n 1 "$TMP/ioc" 2>/dev/null || true)
  [ -n "$first" ] || { ioc_set "$SE/references/indicators.md" > "$TMP/ioc"; first=$(head -n 1 "$TMP/ioc"); }
  local h; h=$(make_fixture "$TMP/fx")
  [ ${#h} -eq 64 ] || { fail "could not build synthetic certificate"; return; }
  # A FIFO planted in the repository must not block the text scans.
  mkfifo "$TMP/fx/proj/trap.txt" 2>/dev/null || true

  # Endpoint blocks run cleanly; E2 completes with no match on a clean runner.
  for i in 1 2 3 4 5; do
    nth_block "$E" sh "$i" > "$TMP/e$i.sh"
    if ! sh "$TMP/e$i.sh" > "$TMP/e$i.out" 2>&1; then
      [ "$i" -eq 3 ] || fail "endpoint block E$i exited non-zero"; fi
  done
  grep -q '^HAVE	openssl' "$TMP/e1.out" || fail "E1 did not find openssl"
  grep -qE '^SUMMARY	files=[1-9][0-9]*	certs=[1-9][0-9]*	hashed=[0-9]+	matches=0	.*complete=yes$' "$TMP/e2.out" \
    || { fail "E2 did not complete cleanly"; cat "$TMP/e2.out" >&2; }
  # Positive endpoint test: the same block with one indicator swapped for the synthetic key.
  sed "s/$first/$h/" "$TMP/e2.sh" > "$TMP/e2pos.sh"
  SSL_CERT_FILE="$TMP/fx/proj/certs/ca-bundle.pem" sh "$TMP/e2pos.sh" > "$TMP/e2pos.out" 2>&1
  grep -q "^MATCH	env:SSL_CERT_FILE	$h$" "$TMP/e2pos.out" || { fail "E2 positive test"; cat "$TMP/e2pos.out" >&2; }
  NODE_TLS_REJECT_UNAUTHORIZED=0 sh "$TMP/e4.sh" > "$TMP/e4pos.out" 2>&1
  grep -q '^ENV	NODE_TLS_REJECT_UNAUTHORIZED	0$' "$TMP/e4pos.out" || fail "E4 TLS flag test"
  ok "endpoint POSIX blocks ($(uname -s))"

  # Project blocks against the fixture.
  for i in 1 2 3 4 5; do nth_block "$P" sh "$i" > "$TMP/p$i.sh"; done
  sed "s/$first/$h/" "$TMP/p3.sh" > "$TMP/p3pos.sh"
  (
    cd "$TMP/fx/proj"
    for i in 1 2 3 4 5; do sh "$TMP/p$i.sh" > "$TMP/p$i.out" 2>&1 || exit 1; done
    sh "$TMP/p3pos.sh" > "$TMP/p3pos.out" 2>&1
  ) || fail "a project block exited non-zero"
  local want; want=$(sed -n 's/^- Example: `\(.*\)`$/\1/p' "$SP/references/tls-rules.md" | wc -l | tr -d ' ')
  for n in $(seq 1 "$want"); do
    grep -q "^\./app\.sh:$n:" "$TMP/p2.out" || fail "P2 missed rule example on line $n: $(sed -n "${n}p" "$TMP/fx/proj/app.sh")"
  done
  grep -q 'node_modules' "$TMP/p2.out" && fail "P2 scanned an excluded directory"
  grep -q "^TOTAL	$((want + 4))$" "$TMP/p2.out" || { fail "P2 unexpected match count"; cat "$TMP/p2.out" >&2; }
  grep -q '^MATCH' "$TMP/p3.out" && fail "P3 false positive"
  grep -q "^MATCH	./certs/ca-bundle.pem	$h$" "$TMP/p3pos.out" || { fail "P3 positive test"; cat "$TMP/p3pos.out" >&2; }
  grep -q '^NO_PEM	./certs/junk.crt$' "$TMP/p3pos.out" || fail "P3 NO_PEM reporting"
  grep -q 'complete=yes' "$TMP/p3pos.out" || fail "P3 completion flag"
  grep -q '^\./uv\.lock$' "$TMP/p1.out" || fail "P1 inventory"
  grep -q 'version = "2026.10.1"' "$TMP/p5.out" || fail "P5 toml lock version"
  grep -q 'FROM node:22.1' "$TMP/p5.out" || fail "P5 container base image"
  grep -q 'node = "22.1.0"' "$TMP/p5.out" || fail "P5 mise tool pin"
  grep -q '"version": "30.0.0"' "$TMP/p5.out" || fail "P5 npm lock version"
  grep -q 'http://<redacted>@pypi.example.invalid' "$TMP/p2.out" || { fail "P2 URL credential redaction"; cat "$TMP/p2.out" >&2; }
  grep -h 's3cr3t' "$TMP"/p[1-5].out && fail "a project block printed a secret"
  # Each documented pattern matches its own example on this platform's grep.
  awk '/^### /{ci = ($NF == "i")} /^- Pattern: /{p = $0; sub(/^- Pattern: `/, "", p); sub(/`$/, "", p)} /^- Example: /{e = $0; sub(/^- Example: `/, "", e); sub(/`$/, "", e); print ci "\t" p "\t" e}' \
    "$SP/references/tls-rules.md" > "$TMP/rules.tsv"
  while IFS="$(printf '\t')" read -r ci p e; do
    if [ "$ci" = 1 ]; then flag=-iE; else flag=-E; fi
    printf '%s\n' "$e" | grep -q $flag -e "$p" || fail "pattern does not match its example: $p"
  done < "$TMP/rules.tsv"
  ok "project POSIX blocks ($(uname -s))"
}

windows_checks() {
  local ps="powershell.exe -NoProfile -NonInteractive -Command -"
  ioc_set "$SE/references/indicators.md" > "$TMP/ioc"
  local first; first=$(head -n 1 "$TMP/ioc")
  local h; h=$(make_fixture "$TMP/wfx")
  block_after_marker "$SE/references/commands-windows.md" windows-endpoint powershell > "$TMP/w1.ps1"
  block_after_marker "$SP/references/commands-windows.md" windows-project powershell > "$TMP/pw1.ps1"
  $ps < "$TMP/w1.ps1" 2>&1 | tr -d '\r' > "$TMP/w1.out" || true
  grep -q '^END$' "$TMP/w1.out" || { fail "W1 did not finish"; cat "$TMP/w1.out" >&2; }
  grep -qE '^SOURCE	store:LocalMachine\\Root	certs=[1-9]' "$TMP/w1.out" || fail "W1 did not read LocalMachine\\Root"
  grep -q '^MATCH' "$TMP/w1.out" && fail "W1 unexpected match on runner"
  sed "s/$first/$h/" "$TMP/w1.ps1" > "$TMP/w1pos.ps1"
  SSL_CERT_FILE=$(cygpath -w "$TMP/wfx/proj/certs/ca-bundle.pem") $ps < "$TMP/w1pos.ps1" 2>&1 | tr -d '\r' > "$TMP/w1pos.out" || true
  grep -q "^MATCH	env:SSL_CERT_FILE	$h$" "$TMP/w1pos.out" || { fail "W1 positive test"; cat "$TMP/w1pos.out" >&2; }
  # A UNC path must be refused before any file-server access.
  SSL_CERT_FILE='\\\\192.0.2.1\\share\\ca.pem' $ps < "$TMP/w1.ps1" 2>&1 | tr -d '\r' > "$TMP/w1unc.out" || true
  grep -q '^NOT_LOCAL_FILE	env:SSL_CERT_FILE$' "$TMP/w1unc.out" || { fail "W1 UNC path refusal"; cat "$TMP/w1unc.out" >&2; }
  grep -q '^END$' "$TMP/w1unc.out" || fail "W1 did not finish with a UNC path"
  ok "endpoint Windows block"
  sed "s/$first/$h/" "$TMP/pw1.ps1" > "$TMP/pw1pos.ps1"
  (cd "$TMP/wfx/proj" && $ps < "$TMP/pw1pos.ps1" 2>&1 | tr -d '\r' > "$TMP/pw1.out") || true
  grep -q '^END$' "$TMP/pw1.out" || { fail "PW1 did not finish"; cat "$TMP/pw1.out" >&2; }
  local want; want=$(grep -c '^- Example: ' "$SP/references/tls-rules.md")
  for n in $(seq 1 "$want"); do
    grep -q "^\.\\\\app\.sh:$n:" "$TMP/pw1.out" || fail "PW1 missed rule example on line $n"
  done
  grep -q "^MATCH	.\\\\certs\\\\ca-bundle.pem	$h$" "$TMP/pw1.out" || { fail "PW1 positive SPKI test"; cat "$TMP/pw1.out" >&2; }
  grep -q '^\.\\node_modules' "$TMP/pw1.out" && fail "PW1 scanned an excluded directory"
  grep -q 'http://<redacted>@pypi.example.invalid' "$TMP/pw1.out" || fail "PW1 URL credential redaction"
  grep -q 'node = "22.1.0"' "$TMP/pw1.out" || fail "PW1 mise tool pin"
  grep 's3cr3t' "$TMP/pw1.out" && fail "PW1 printed a secret"
  ok "project Windows block"
}

case "$MODE" in
  static) static_checks ;;
  posix) static_checks; posix_checks ;;
  windows) windows_checks ;;
  all) static_checks; posix_checks ;;
  *) echo "usage: $0 [static|posix|windows|all]" >&2; exit 2 ;;
esac

if [ "$FAILS" -gt 0 ]; then printf '%d check(s) failed\n' "$FAILS" >&2; exit 1; fi
echo 'all checks passed'
