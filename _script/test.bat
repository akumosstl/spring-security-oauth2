REM === Execute curl to retrieve token ===

curl -X POST http://localhost:9000/oauth2/token ^
  -H "Authorization: Basic YXBpLWNsaWVudDpzZWNyZXQ=" ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "grant_type=client_credentials&scope=message.read"

pause
REM
REM  YXBpLWNsaWVudDpzZWNyZXQ=
REM  dXNlcjpwYXNzd29yZA==