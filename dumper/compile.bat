go build -ldflags "-H windowsgui -s -w" -i
upx.exe -9 experements.exe
pause

