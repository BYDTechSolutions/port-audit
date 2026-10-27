#!/usr/bin/env bash
# The GitHub Action's one step (see action.yml). Inputs arrive as INPUT_* env
# vars, never pasted into the script, so their text cannot run as shell code.
# One scan writes every format: text for the log, Markdown for the job summary,
# JSON for the outputs, SARIF for code scanning.
set -uo pipefail

fail() {
  echo "::error title=port-audit::$1"
  exit 2
}
lines() { printf '%s\n' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d'; }

command -v node >/dev/null 2>&1 || fail "Node.js 20 or newer is needed. Add actions/setup-node before this step."
major=$(node -p 'process.versions.node.split(".")[0]')
[ "$major" -ge 20 ] || fail "Node.js 20 or newer is needed, found $(node -v). Add actions/setup-node with node-version: 22 before this step."

pkg="${INPUT_PACKAGE:-}"
if [ -z "$pkg" ]; then
  version=$(node -p 'require(process.argv[1]).version' "$GITHUB_ACTION_PATH/package.json")
  pkg="@bydtech/port-audit@$version"
fi

target="${INPUT_TARGET:-3000}"
if [[ "$target" =~ ^[0-9]+$ ]]; then url="http://localhost:$target/"; else url="$target"; fi

wait="${INPUT_WAIT:-60}"
[[ "$wait" =~ ^[0-9]+$ ]] || fail "wait must be a number of seconds, got \"$wait\"."
if [ "$wait" -gt 0 ]; then
  echo "Waiting up to ${wait}s for $url to answer..."
  deadline=$((SECONDS + wait))
  until curl -sk -o /dev/null --max-time 5 "$url"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "$url did not answer within ${wait}s. Start the app in an earlier step, in the background (for example: npm start &), or raise the wait input."
    fi
    sleep 2
  done
fi

out="${RUNNER_TEMP:-/tmp}/port-audit"
mkdir -p "$out"
rm -f "$out/report.txt" "$out/report.md" "$out/report.json"

args=("$target" --quiet --no-color -o "$out/report.txt" -o "$out/report.md" -o "$out/report.json")
[ -n "${INPUT_SARIF_FILE:-}" ] && args+=(-o "$INPUT_SARIF_FILE")
while IFS= read -r p; do args+=(--path "$p"); done < <(lines "${INPUT_PATHS:-}")
while IFS= read -r h; do args+=(--header "$h"); done < <(lines "${INPUT_HEADERS:-}")
[ -n "${INPUT_BASELINE:-}" ] && args+=(--baseline "$INPUT_BASELINE")
[ -n "${INPUT_FRAMEWORK:-}" ] && args+=(--framework "$INPUT_FRAMEWORK")
[ -n "${INPUT_I_OWN_THIS:-}" ] && args+=(--i-own-this "$INPUT_I_OWN_THIS")
fail_on="${INPUT_FAIL_ON-fix-now}"
case "$fail_on" in
  none | '') ;;
  fix-now | should-fix) args+=(--fail-on "$fail_on") ;;
  *) fail "fail-on must be fix-now, should-fix or none, got \"$fail_on\"." ;;
esac
if [ -n "${INPUT_ARGS:-}" ]; then
  read -r -a extra <<< "$INPUT_ARGS"
  args+=("${extra[@]}")
fi

echo "Running $pkg"
npx --yes --package="$pkg" -- port-audit "${args[@]}"
code=$?

[ -f "$out/report.txt" ] || exit "$code"
echo
cat "$out/report.txt"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  if [ "$(wc -c < "$out/report.md")" -lt 1000000 ]; then
    cat "$out/report.md" >> "$GITHUB_STEP_SUMMARY"
  else
    echo "The port-audit report is too large for the job summary; it is in the log above." >> "$GITHUB_STEP_SUMMARY"
  fi
fi

node -e '
const r = require(process.argv[1]);
const n = (p) => r.findings.filter((f) => f.priority === p).length;
console.log(`fix-now=${n("fix-now")}\nshould-fix=${n("should-fix")}\nnice-to-have=${n("nice-to-have")}`);
' "$out/report.json" >> "${GITHUB_OUTPUT:-/dev/null}"
{
  echo "report-json=$out/report.json"
  echo "report-md=$out/report.md"
  echo "sarif-file=${INPUT_SARIF_FILE:-}"
} >> "${GITHUB_OUTPUT:-/dev/null}"

[ "$code" -eq 1 ] && echo "::error title=port-audit::Findings at fail-on $fail_on or above. The report is in the log and the job summary."
exit "$code"
