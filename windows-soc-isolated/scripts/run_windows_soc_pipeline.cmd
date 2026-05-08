@echo off
setlocal EnableExtensions

rem Run the isolated Windows SOC pipeline from inside windows-soc-isolated.
rem Examples:
rem   scripts\run_windows_soc_pipeline.cmd
rem   scripts\run_windows_soc_pipeline.cmd -MaxEvents 3000
rem   scripts\run_windows_soc_pipeline.cmd -PublishToElasticsearch -ElasticPassword <password>

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_windows_soc_pipeline.ps1" %*
exit /b %ERRORLEVEL%
