$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$examplePath = Join-Path $projectRoot ".env.example"
$envPath = Join-Path $projectRoot ".env"

if (Test-Path -LiteralPath $envPath) {
  throw ".env already exists. Keep it intact and edit it directly if needed."
}

function New-RandomHex([int]$byteCount) {
  $bytes = [byte[]]::new($byteCount)
  $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $generator.GetBytes($bytes)
  } finally {
    $generator.Dispose()
  }
  return [Convert]::ToHexString($bytes).ToLowerInvariant()
}

$jwtSecret = New-RandomHex 48
$databasePassword = New-RandomHex 24
$content = [System.IO.File]::ReadAllText($examplePath)
$content = [regex]::Replace($content, "(?m)^JWT_SECRET=.*$", "JWT_SECRET=$jwtSecret")
$content = [regex]::Replace(
  $content,
  "(?m)^POSTGRES_PASSWORD=.*$",
  "POSTGRES_PASSWORD=$databasePassword"
)
$content = [regex]::Replace(
  $content,
  "(?m)^DATABASE_URL=.*$",
  "DATABASE_URL=postgresql+psycopg://ascent:$databasePassword@db:5432/ascent"
)
[System.IO.File]::WriteAllText($envPath, $content, [System.Text.UTF8Encoding]::new($false))
Write-Host "Created .env with fresh local secrets. Review deployment-specific settings before production use."
