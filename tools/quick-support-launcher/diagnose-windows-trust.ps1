# CI-only probe: no artifact execution, trust overrides, or customer information.
$ErrorActionPreference = 'Stop'
if (-not $env:BIFROST_QS_TEST_SIGNED_ARTIFACT) { throw 'Pinned fixture unavailable' }
$windows = [Environment]::GetFolderPath('Windows')
$systemPowerShell = Join-Path $windows 'System32\WindowsPowerShell\v1.0'
$script = @'
$ErrorActionPreference = 'Stop'
[Console]::WriteLine('[QS-TRUST] started-ms=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
$module = $PSHOME + '\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
try {
    if ($env:BIFROST_QS_PROBE_MODE -eq 'joined') {
        $module = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
        Import-Module -Name $module -ErrorAction Stop
    }
    if ($env:BIFROST_QS_PROBE_MODE -eq 'manifest') { Import-Module -Name $module -ErrorAction Stop }
    if ($env:BIFROST_QS_PROBE_MODE -eq 'gac') {
        $assembly = [Reflection.Assembly]::Load('Microsoft.PowerShell.Security, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35')
        Import-Module -Assembly $assembly -ErrorAction Stop
    }
    [Console]::WriteLine('[QS-TRUST] module-ms=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $env:BIFROST_QS_ARTIFACT
    [Console]::WriteLine('[QS-TRUST] status=' + [int]$signature.Status)
    exit 0
} catch {
    [Console]::WriteLine('[QS-TRUST] error-type=' + $_.Exception.GetType().FullName)
    exit 1
}
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
# Compare module initialization in the same restricted environment.
# Each probe retains the same 30-second bound; a pass never waives the failed test.
foreach ($mode in @('joined', 'manifest')) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $systemPowerShell 'powershell.exe'
    $start.Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $start.WorkingDirectory = $systemPowerShell
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment.Clear()
    $start.Environment['SystemRoot'] = $windows
    $start.Environment['windir'] = $windows
    $start.Environment['PSModulePath'] = Join-Path $systemPowerShell 'Modules'
    $start.Environment['BIFROST_QS_PROBE_MODE'] = $mode
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
            if ($line -match '^\[QS-TRUST\] (started-ms=[0-9]+|module-ms=[0-9]+|status=[0-9]+|error-type=[A-Za-z0-9.]{1,120})$') {
                Write-Output $line
            }
        }
        [void]$errors.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
}
