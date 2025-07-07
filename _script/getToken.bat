@echo off
rem This script is intended to directly fetch a token from the authorization-server
rem using the client_credentials grant type.

rem Original problematic command (commented out for clarity):
rem curl -X POST http://localhost:8080/oauth2/token ^
rem  -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" ^
rem  -H "Content-Type: application/x-www-form-urlencoded" ^
rem  -d "grant_type=client_credentials&scope=message.read"

@echo on
echo Requesting token from authorization-server (port 9000) with client_credentials grant...
curl -k -X POST http://localhost:9000/oauth2/token ^
  -H "Authorization: Basic Y2xpZW50OnNlY3JldA==" ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "grant_type=client_credentials&scope=openid message.read"

echo.
echo.
echo For reference, to get a token using password grant (user:password, client:secret):
echo curl -k -X POST http://localhost:9000/oauth2/token -H "Authorization: Basic Y2xpZW50OnNlY3JldA==" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=password&username=user&password=password&scope=openid message.read"
