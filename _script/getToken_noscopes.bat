@echo off
echo Requesting token with NO scopes (client_credentials grant)...
echo Target: http://localhost:9000/oauth2/token
echo Client ID: client, Client Secret: secret
echo Grant Type: client_credentials
echo.

curl -k -X POST http://localhost:9000/oauth2/token ^
  -H "Authorization: Basic Y2xpZW50OnNlY3JldA==" ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "grant_type=client_credentials"

echo.
echo.
echo Script finished.
