@echo off
rem curl -X POST "http://localhost:8081/oauth2/token" -H "Content-Type: application/x-www-form-urlencoded" -H "Authorization: Basic YXBpLWNsaWVudDpzZWNyZXQ=" -d "grant_type=client_credentials&scope=message.read"

@echo off
curl -X POST http://localhost:8080/oauth2/token ^
  -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "grant_type=client_credentials&scope=message.read"