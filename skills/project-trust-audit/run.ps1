# Arguments remain arguments; no Invoke-Expression or interpolated command text.
$ErrorActionPreference = 'Stop'
$binary = $env:EMUDHRA_TRUST_AUDIT_BIN
if ($binary) {
    if (-not [System.IO.Path]::IsPathRooted($binary)) {
        [Console]::Error.WriteLine('EMUDHRA_TRUST_AUDIT_BIN must be an absolute trusted executable path.')
        exit 3
    }
} elseif (Test-Path -LiteralPath "$PSScriptRoot/bin/emudhra-trust-audit.exe" -PathType Leaf) {
    $binary = "$PSScriptRoot/bin/emudhra-trust-audit.exe"
} else {
    $candidate = Get-Command emudhra-trust-audit -CommandType Application -ErrorAction SilentlyContinue
    if ($candidate) { $binary = $candidate.Source }
}
if (-not $binary -or -not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    [Console]::Error.WriteLine('emudhra-trust-audit is missing. Install a verified binary from https://github.com/NobukazuHanada/emudhra-trust-audit/releases or build with Cargo. Set EMUDHRA_TRUST_AUDIT_BIN to its absolute path. Nothing was downloaded or executed.')
    exit 3
}
& $binary project @args
exit $LASTEXITCODE
