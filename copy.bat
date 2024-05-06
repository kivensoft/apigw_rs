@echo off
rem 目录定时同步脚本
set project=apigw
set src=/f/%project%/
set dst=/d/develop/rust/%project%/

rsync -av --exclude="/target/" --exclude="/.git/" %dst% %src%
