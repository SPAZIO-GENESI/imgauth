param(
  # Esempio: "test-pdf-certificato-imgauth" (senza dominio)
  [Parameter(Mandatory = $true)]
  [string]$PreviewAlias,

  # Nome worker (default: da wrangler.toml / progetto)
  [string]$WorkerName = "",

  # Se true: non esegue wrangler, stampa solo i comandi
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Exec([string]$cmd) {
  $out = & powershell -NoProfile -Command $cmd
  if ($LASTEXITCODE -ne 0) { throw "Command failed: $cmd" }
  return ($out | Out-String).Trim()
}

$branch  = Exec "git rev-parse --abbrev-ref HEAD"
$sha     = Exec "git rev-parse --short HEAD"
$subject = Exec "git log -1 --pretty=%s"

# Tag: compatibile con wrangler (evita spazi e caratteri strani)
$tag = ($branch -replace '[^a-zA-Z0-9._/-]', '-')

# Message: cosa serve per capire in dashboard
$message = ("{0}@{1} - {2}" -f $branch, $sha, $subject)

$args = @("wrangler", "versions", "upload")
if ($WorkerName -and $WorkerName.Trim().Length -gt 0) {
  $args += @("--name", $WorkerName)
}
$args += @("--preview-alias", $PreviewAlias, "--tag", $tag, "--message", $message)

if ($DryRun) {
  Write-Output ("npx " + ($args | ForEach-Object { if ($_ -match '\s') { '"' + $_.Replace('"','\"') + '"' } else { $_ } }) -join " ")
  exit 0
}

Write-Output "Uploading version with:"
Write-Output "  message: $message"
Write-Output "  tag:     $tag"
Write-Output "  alias:   $PreviewAlias"
Write-Output ""

& npx @args
if ($LASTEXITCODE -ne 0) { throw "wrangler upload failed" }
