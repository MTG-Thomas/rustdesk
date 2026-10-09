[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$PublisherSubject,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$UnsignedSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or $env:GITHUB_ACTIONS -ne 'true' -or [string]::IsNullOrWhiteSpace($PublisherSubject)) {
    throw 'Private verification requires an ephemeral Windows Actions runner and an approved publisher.'
}
$rootPath = Join-Path $env:RUNNER_TEMP 'quick-support-private-root.cer'
$expectedRoot = 'D549DC2314F7A16E496A515491B273BC9C098E40A070D61EF1602870F0C402D8'
Invoke-WebRequest -Uri 'https://www.microsoft.com/pkiops/certs/Microsoft%20Enterprise%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt' -OutFile $rootPath
if ((Get-FileHash -LiteralPath $rootPath -Algorithm SHA256).Hash -ne $expectedRoot) { throw 'Microsoft private root digest mismatch.' }
$root = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($rootPath))
$storePath = "Cert:\CurrentUser\Root\$($root.Thumbprint)"
$existed = Test-Path -LiteralPath $storePath
try {
    if ($root.HasPrivateKey -or $root.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Invalid public root certificate.' }
    if (-not $existed) { Import-Certificate -FilePath $rootPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null }
    $signature = Get-AuthenticodeSignature -LiteralPath $Executable
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -cne $PublisherSubject -or -not $signature.TimeStamperCertificate) {
        throw 'Private signature, publisher or timestamp verification failed.'
    }
    $ekus = @($signature.SignerCertificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if ('1.3.6.1.5.5.7.3.3' -notin $ekus -or -not ($ekus | Where-Object { $_.StartsWith('1.3.6.1.4.1.311.97.1.3.1.') })) {
        throw 'Private Trust code-signing certificate required.'
    }
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30)
        # Authenticode above validates the actual timestamp. Check the short-lived
        # signer chain during its validity interval as a separate root check.
        $chain.ChainPolicy.VerificationTime = $signature.SignerCertificate.NotBefore.AddMinutes(1)
        if (-not $chain.Build($signature.SignerCertificate)) { throw 'Private chain verification failed.' }
        $chainRoot = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $actualRoot = [BitConverter]::ToString($hash.ComputeHash($chainRoot.RawData)).Replace('-', '') } finally { $hash.Dispose() }
        if ($actualRoot -ne $expectedRoot) { throw 'Unexpected private certificate authority.' }
    } finally { $chain.Dispose() }
    $signedHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
    if ($signedHash -eq $UnsignedSha256) { throw 'Artifact was not changed by signing.' }
    [ordered]@{
        scope = 'quick-support-private-signing-rehearsal'; source_commit = $SourceCommit
        unsigned_sha256 = $UnsignedSha256; signed_sha256 = $signedHash
        publisher = $signature.SignerCertificate.Subject; signature_status = [string]$signature.Status
        signer_thumbprint = $signature.SignerCertificate.Thumbprint
        timestamp_thumbprint = $signature.TimeStamperCertificate.Thumbprint
        private_root_sha256 = $actualRoot; account = 'mtg-sopdet-signing'; profile = 'mtg-lab-profile'
        producer_run = $env:GITHUB_RUN_ID; producer_attempt = $env:GITHUB_RUN_ATTEMPT
    } | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding utf8
} finally {
    if (-not $existed -and (Test-Path -LiteralPath $storePath)) { Remove-Item -LiteralPath $storePath }
    $root.Dispose()
    Remove-Item -LiteralPath $rootPath
}
