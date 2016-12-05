@ECHO OFF
SETLOCAL
SET _SCANGROUP=
SET _CREATEHOSTSFILE=

:parse
IF "%~1"=="" GOTO endparse
SET _test=%~1
IF /I "%~1"=="-scangroup" (SET _SCANGROUP=%~2) ELSE (IF /I "%~1"=="-createHostsFile" SET _CREATEHOSTSFILE=%~2)
SHIFT
GOTO parse
:endparse

IF "%_SCANGROUP%"=="" (
  ECHO Scan group is not specified via -scangroup parameter. Exiting...
  @ECHO ON
  EXIT /b
)

IF /I "%_CREATEHOSTSFILE%"=="yes" (SET _CREATEHOSTSFILE=true) ELSE (IF /I "%_CREATEHOSTSFILE%"=="true" (SET _CREATEHOSTSFILE=true) ELSE (SET _CREATEHOSTSFILE=false))

:: Based on http://ss64.com/nt/syntax-getdate.html
:: Check if WMIC is available
WMIC.EXE Alias /? >NUL 2>&1 || GOTO ts_error

:: Use WMIC to retrieve date and time
FOR /F "skip=1 tokens=1-6" %%G IN ('WMIC Path Win32_LocalTime Get Day^,Hour^,Minute^,Month^,Second^,Year /Format:table') DO (
  IF "%%~L"=="" GOTO ts_done
    SET _yyyy=%%L
    SET _mm=00%%J
    SET _dd=00%%G
    SET _hour=00%%H
    SET _minute=00%%I
    SET _second=00%%K
)
:ts_done

:: Pad digits with leading zeros
SET _mm=%_mm:~-2%
SET _dd=%_dd:~-2%
SET _hour=%_hour:~-2%
SET _minute=%_minute:~-2%
SET _second=%_second:~-2%

SET _TIMESTAMP=%_yyyy%-%_mm%-%_dd%_%_hour%.%_minute%.%_second%

:ts_error
IF "%_TIMESTAMP%"=="" (SET _TIMESTAMP=%date:~10%-%date:~4,2%-%date:~7,2%)

:: Hosts file
IF NOT "%_CREATEHOSTSFILE%"=="true" GOTO end_hosts
@ECHO ON
:: Backup existing file
::MOVE .\data\hosts\hosts%_SCANGROUP%.txt .\data\backups\hosts\hosts%_SCANGROUP%_%_TIMESTAMP%.txt
IF EXIST .\data\hosts\hosts%_SCANGROUP%.txt CALL "C:\Program Files\WinRAR\winrar.exe" a -ep -afzip .\data\backups\hosts\hosts%_SCANGROUP%_%_TIMESTAMP%.zip .\data\hosts\hosts%_SCANGROUP%.txt
:: Create hosts list from domains JSON
CALL PYTHON ./scripts/createHostsFile.py --domainsfile=./data/domains/domains%_SCANGROUP%.json > ./data/hosts/hosts%_SCANGROUP%.txt
:end_hosts

:: Use Fiddler when running behind proxy unless you want to configure proxy for Python and Go
::SET http_proxy=127.0.0.1:8888

@ECHO ON
:: Get SSL Labs results for hosts
:: Backup existing file
IF EXIST .\data\ssllabsReports\ssllabsReport%_SCANGROUP%.json CALL "C:\Program Files\WinRAR\winrar.exe" a -ep -afzip .\data\backups\ssllabsReports\ssllabsReport%_SCANGROUP%_%_TIMESTAMP%.zip .\data\ssllabsReports\ssllabsReport%_SCANGROUP%.json
CALL GO run ./scripts/ssllabs-scan.go --usecache=true --maxage=24 --ignore-mismatch=true --hostfile ./data/hosts/hosts%_SCANGROUP%.txt > ./data/ssllabsReports/ssllabsReport%_SCANGROUP%.json

:: Create data set for site report
IF EXIST .\data\dataSets\dataSet%_SCANGROUP%.js CALL "C:\Program Files\WinRAR\winrar.exe" a -ep -afzip .\data\backups\dataSets\dataSet%_SCANGROUP%_%_TIMESTAMP%.zip .\data\dataSets\dataSet%_SCANGROUP%.js
CALL PYTHON ./scripts/createDataSet.py --domainsfile=./data/domains/domains%_SCANGROUP%.json --ssllabsreportsfile=./data/ssllabsReports/ssllabsReport%_SCANGROUP%.json > ./data/dataSets/dataSet%_SCANGROUP%.js

@ECHO OFF
ENDLOCAL
@ECHO ON
