param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$FilePath
)

$ErrorActionPreference = "Stop"

foreach ($name in 'ESIGNER_USERNAME','ESIGNER_PASSWORD','ESIGNER_CREDENTIAL_ID','ESIGNER_TOTP_SECRET','CODE_SIGN_TOOL_DIR') {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Environment variable $name is not set"
    }
}

$jar = Get-ChildItem -Path (Join-Path $env:CODE_SIGN_TOOL_DIR 'jar') -Filter 'code_sign_tool-*.jar' | Select-Object -First 1
if (-not $jar) { throw "CodeSignTool jar not found under $env:CODE_SIGN_TOOL_DIR\jar" }

Write-Host "Signing $FilePath"

# CodeSignTool reads conf/code_sign_tool.properties relative to CWD, so run from its root dir.
Push-Location $env:CODE_SIGN_TOOL_DIR
try {
    & java -jar $jar.FullName sign `
        "-username=$env:ESIGNER_USERNAME" `
        "-password=$env:ESIGNER_PASSWORD" `
        "-credential_id=$env:ESIGNER_CREDENTIAL_ID" `
        "-totp_secret=$env:ESIGNER_TOTP_SECRET" `
        "-input_file_path=$FilePath" `
        -override
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($code -ne 0) { throw "CodeSignTool failed with exit code $code for $FilePath" }
Write-Host "Signed $FilePath"
