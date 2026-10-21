$BASE = "C:\Users\ansh8\.gemini\antigravity\scratch\reg-log-backend"
Set-Location $BASE

$env:JAVA_HOME = "C:\Program Files\Java\jdk-24"
$JAVA_EXE = "$env:JAVA_HOME\bin\java.exe"

# Load environment variables from .env
Get-Content "$BASE\.env" | Where-Object { $_ -match '^[^#]' -and $_.Trim() -ne '' } | ForEach-Object {
    $parts = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), 'Process')
}

Write-Host "Starting Spring Boot Backend on http://localhost:8080..."
& "$JAVA_EXE" -jar "$BASE\target\reg-log-backend-1.0.0.jar"
