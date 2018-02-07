@echo off

if exist joelcrypto_cygwin.exe (
	set executable=joelcrypto_cygwin.exe
)

if exist joelcrypto.exe (
	set executable=joelcrypto.exe
)

if %executable%=="" (
	echo Executable not found
	pause
	exit
)

echo Using executable %executable%

%executable% --encrypt -i file:test_alph.txt -o file:test_alph.inprogress -c caesar > nul
%executable% --decrypt -i file:test_alph.inprogress -o file:test_alph.end -c caesar > nul
call :CheckResult "Caesar cipher" "test_alph.txt" "test_alph.end"

set /a key=%random% %% 26
%executable% --encrypt -i file:test_alph.txt -o file:test_alph.inprogress -c shift -k text:%key% > nul
%executable% --decrypt -i file:test_alph.inprogress -o file:test_alph.end -c shift -k text:%key% > nul
call :CheckResult "Shift cipher" "test_alph.txt" "test_alph.end"

set /a key=WTGHYJUK
%executable% --encrypt -i file:test_alph.txt -o file:test_alph.inprogress -c vigenere -k text:%key% > nul
%executable% --decrypt -i file:test_alph.inprogress -o file:test_alph.end -c vigenere -k text:%key% > nul
call :CheckResult "Vigenere cipher" "test_alph.txt" "test_alph.end"

set key=6Hr4SdO9y7Hfw3y45Gk3dy1aqQshJou7TgrERRE610m=

%executable% --encrypt -i file:test_ascii.txt -o file:test_ascii.inprogress -c RC4 -k base64:%key% > nul
%executable% --decrypt -i file:test_ascii.inprogress -o file:test_ascii.end -c RC4 -k base64:%key% > nul
call :CheckResult "RC4 cipher" "test_ascii.txt" "test_ascii.end"
		
set iv=qRA67ZlOFFnJj8cRTEt2hw==
		
for %%b in (128 192 256) do (
	for %%m in (ECB CBC OFB CFB CTR) do (
		%executable% --encrypt -i file:test_ascii.txt -o file:test_ascii.inprogress -c AES:%%b:%%m -k base64:%key% -iv base64:%iv% > nul
		%executable% --decrypt -i file:test_ascii.inprogress -o file:test_ascii.end -c AES:%%b:%%m -k base64:%key% -iv base64:%iv% > nul
		call :CheckResult "AES:%%b:%%m cipher" "test_ascii.txt" "test_ascii.end"
	)
)

del test_alph.inprogress
del test_ascii.inprogress
del test_alph.end
del test_ascii.end

echo Tests completed
pause
exit


:: Test name, outfile1, outfile2
:CheckResult
	if %errorlevel%==0 (
		fc /B %2 %3 > nul
		if %errorlevel%==0 (
			echo %~1 test passed
		) else (
			echo %~1 test failed: unencrypted and decrypted files do not match
		)
	) else (
		echo %~1 test failed: program returned error code %errorlevel%
	)
	exit /b