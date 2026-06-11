@echo off
setlocal enabledelayedexpansion

:: === FIX UNICODE ENCODING ===
chcp 65001 >nul
set PYTHONIOENCODING=utf-8

:: === CONFIGURATION ===
set BASE_URL=http://localhost:5000
set SPEC_URL=http://localhost:5000/openapi.json
set TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzU1NDM2NDEsImlhdCI6MTc3NTUyNTY0MSwic3ViIjoiYXR0YWNrZXIifQ.UWSCqYjYK5KQG_td9RlGoWH4oksFxY15uW6WTk0s2ZU
set SEED=12345
set MAX_EXAMPLES=20
set RESULTS_DIR=results\vampi_bac

:: Create results directory
if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

echo =====================================================
echo    VAmPI BAC Fuzzing Suite - Schemathesis 4.10.2
echo =====================================================
echo.

:: === TEST 1: BOLA - /books/v1/{book_title} ===
echo [1/5] Testing BOLA: /books/v1/{book_title}...
schemathesis run %SPEC_URL% ^
  --url %BASE_URL% ^
  --header "Authorization: Bearer %TOKEN%" ^
  --include-path-regex "/books/v1/.*" ^
  --checks not_a_server_error ^
  --exclude-checks response_schema_conformance,content_type_conformance,response_headers_conformance ^
  --max-examples %MAX_EXAMPLES% ^
  --seed %SEED% ^
  --no-color ^
  --report ndjson --report-ndjson-path "%RESULTS_DIR%\books.ndjson"
echo.

:: === TEST 2: BOLA - /users/v1/{username}/password ===
echo [2/5] Testing BOLA: /users/v1/{username}/password...
schemathesis run %SPEC_URL% ^
  --url %BASE_URL% ^
  --header "Authorization: Bearer %TOKEN%" ^
  --include-path-regex "/users/v1/.*/password" ^
  --checks not_a_server_error ^
  --exclude-checks response_schema_conformance,content_type_conformance,response_headers_conformance ^
  --max-examples %MAX_EXAMPLES% ^
  --seed %SEED% ^
  --no-color ^
  --report ndjson --report-ndjson-path "%RESULTS_DIR%\password.ndjson"
echo.

:: === TEST 3: BFLA - /users/v1/_debug ===
echo [3/5] Testing BFLA: /users/v1/_debug...
schemathesis run %SPEC_URL% ^
  --url %BASE_URL% ^
  --header "Authorization: Bearer %TOKEN%" ^
  --include-path-regex "/users/v1/_debug" ^
  --checks not_a_server_error ^
  --exclude-checks response_schema_conformance,content_type_conformance,response_headers_conformance ^
  --max-examples %MAX_EXAMPLES% ^
  --seed %SEED% ^
  --no-color ^
  --report ndjson --report-ndjson-path "%RESULTS_DIR%\debug.ndjson"
echo.

:: === TEST 4: BFLA - Mass Assignment on /users/v1/register ===
echo [4/5] Testing BFLA: Mass Assignment on /users/v1/register...
schemathesis run %SPEC_URL% ^
  --url %BASE_URL% ^
  --header "Authorization: Bearer %TOKEN%" ^
  --include-path-regex "/users/v1/register" ^
  --checks not_a_server_error ^
  --exclude-checks response_schema_conformance,content_type_conformance,response_headers_conformance ^
  --max-examples %MAX_EXAMPLES% ^
  --seed %SEED% ^
  --no-color ^
  --report ndjson --report-ndjson-path "%RESULTS_DIR%\register.ndjson"
echo.

:: === TEST 5: Enumeration - /users/v1/login ===
echo [5/5] Testing Enumeration: /users/v1/login...
schemathesis run %SPEC_URL% ^
  --url %BASE_URL% ^
  --header "Authorization: Bearer %TOKEN%" ^
  --include-path-regex "/users/v1/login" ^
  --checks not_a_server_error ^
  --exclude-checks response_schema_conformance,content_type_conformance,response_headers_conformance ^
  --max-examples %MAX_EXAMPLES% ^
  --seed %SEED% ^
  --no-color ^
  --report ndjson --report-ndjson-path "%RESULTS_DIR%\login.ndjson"
echo.

echo =====================================================
echo    All tests complete. Results saved to: %RESULTS_DIR%
echo =====================================================
pause