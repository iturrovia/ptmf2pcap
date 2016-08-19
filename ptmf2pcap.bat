@echo off
set PATH=%PATH%;"C:\Program Files (x86)\Java\jre7\bin"
java -cp %~dp0\ptmf2pcap.jar ptmf2pcap.Cli %*
