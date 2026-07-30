Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting Mini Vault using Docker Compose..." -ForegroundColor Green
Write-Host "This will build the containers and start the app." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
docker compose up --build
