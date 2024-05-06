@echo off
rem 目录定时同步脚本
set project=apigw
set src=/f/%project%/
set dst=/d/develop/rust/%project%/

if "%1" == "once" goto loop

echo Synchronize folders:
echo    %src%  ^<=^>  %dst%
set /p var="Are you sure?(y/n)"
if %var%==n goto end

:loop
    rsync -av --delete --exclude="/target/" --exclude="/.git/" %src% %dst%
    if "%1" == "once" goto end
    echo waiting for synchronize folders %src% =^> %dst%
    timeout /t 600
    goto loop

:end
