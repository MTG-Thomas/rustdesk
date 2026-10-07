# CI-only probe: no artifact execution, trust overrides, or customer information.
$ErrorActionPreference = 'Stop'
if (-not $env:BIFROST_QS_TEST_SIGNED_ARTIFACT) { throw 'Pinned fixture unavailable' }
$windows = [Environment]::GetFolderPath('Windows')
$systemPowerShell = Join-Path $windows 'System32\WindowsPowerShell\v1.0'
$script = @'
$ErrorActionPreference = 'Stop'
Write-Output ('[QS-TRUST] started-ms=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
Write-Output ('[QS-TRUST] module-ms=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
Write-Output ('[QS-TRUST] execution-policy=' + (Microsoft.PowerShell.Security\Get-ExecutionPolicy))
$signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $env:BIFROST_QS_ARTIFACT
Write-Output ('[QS-TRUST] status=' + [int]$signature.Status)
exit 0
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
# Compare the normal CI environment with the launcher's deliberately narrow one.
# Each probe retains the same 30-second bound; a pass never waives the failed test.
foreach ($mode in @('restricted', 'restricted-auto-modules', 'inherited-system-modules', 'inherited')) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $systemPowerShell 'powershell.exe'
    $start.Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $start.WorkingDirectory = $systemPowerShell
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if (-not $mode.StartsWith('inherited')) {
        $start.Environment.Clear()
        $start.Environment['SystemRoot'] = $windows
        $start.Environment['windir'] = $windows
    }
    if ($mode -eq 'restricted' -or $mode -eq 'inherited-system-modules') {
        $start.Environment['PSModulePath'] = Join-Path $systemPowerShell 'Modules'
    }
    $start.Environment['BIFROST_QS_ARTIFACT'] = $env:BIFROST_QS_TEST_SIGNED_ARTIFACT
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        [void]$process.Start()
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit(30000)
        if (-not $finished) { $process.Kill($true); $process.WaitForExit() }
        Write-Output "[QS-TRUST] mode=$mode finished=$finished elapsed-ms=$($timer.ElapsedMilliseconds)"
        Write-Output "[QS-TRUST] exit-code=$($process.ExitCode)"
        # Only constant stage markers or a numeric SignatureStatus may be logged.
        foreach ($line in ($output.GetAwaiter().GetResult() -split '\r?\n')) {
            if ($line -match '^\[QS-TRUST\] (started-ms=[0-9]+|module-ms=[0-9]+|status=[0-9]+|execution-policy=(AllSigned|Bypass|Default|RemoteSigned|Restricted|Undefined|Unrestricted))$') {
                Write-Output $line
            }
        }
        [void]$errors.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
}
