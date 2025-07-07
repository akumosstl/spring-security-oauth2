@echo off
setlocal

REM === Configuration ===
set CLIENT_ID=api-client
set CLIENT_SECRET=secret
set USERNAME=user
set PASSWORD=password
set TOKEN_URL=http://localhost:9000/oauth2/token

REM === Encode client_id:client_secret in base64 ===
set CREDENTIALS=%CLIENT_ID%:%CLIENT_SECRET%

echo %CREDENTIALS%> tmp.txt
certutil -encode tmp.txt tmp.b64 >nul
for /f "skip=1 delims=" %%a in (tmp.b64) do (
    if not defined BASIC_AUTH (
        set BASIC_AUTH=%%a
    )
)

REM === Clean up temporary files ===
del tmp.txt
del tmp.b64

REM === Execute curl to retrieve token ===
curl -X POST %TOKEN_URL% ^
  -H "Authorization: Basic %BASIC_AUTH%" ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "grant_type=password&username=%USERNAME%&password=%PASSWORD%"

pause
