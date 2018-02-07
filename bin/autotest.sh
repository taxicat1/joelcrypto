#!/bin/bash

# Test name, outfile1, outfile2
check_result() {
	if [ $? == 0 ]
	then
		cmp --silent $2 $3
		if [ $? == 0 ]
		then
			echo "$1 test passed"
		else
			echo "$1 test failed: unencrypted and decrypted files do not match"
		fi
	else
		echo "$1 test failed: program returned error code $?"
	fi
}

if ! [ -x joelcrypto ]
then
	echo Executable not found
	read -n 1 -p "Press any key to continue..."
	exit
fi

echo "Using executable joelcrypto"

./joelcrypto --encrypt -i file:test_alph.txt -o file:test_alph.inprogress -c caesar > /dev/null
./joelcrypto --decrypt -i file:test_alph.inprogress -o file:test_alph.end -c caesar > /dev/null
check_result "Caesar cipher" "test_alph.txt" "test_alph.end"

key=$(($RANDOM % 26))
./joelcrypto --encrypt -i file:test_alph.txt -o file:test_alph.inprogress -c shift -k text:$key > /dev/null
./joelcrypto --decrypt -i file:test_alph.inprogress -o file:test_alph.end -c shift -k text:$key > /dev/null
check_result "Shift cipher" "test_alph.txt" "test_alph.end"

key="WTGHYJUK"
./joelcrypto --encrypt -i file:test_alph.txt -o file:test_alph.inprogress -c vigenere -k text:$key > /dev/null
./joelcrypto --decrypt -i file:test_alph.inprogress -o file:test_alph.end -c vigenere -k text:$key > /dev/null
check_result "Vigenere cipher" "test_alph.txt" "test_alph.end"

key="6Hr4SdO9y7Hfw3y45Gk3dy1aqQshJou7TgrERRE610m="

./joelcrypto --encrypt -i file:test_ascii.txt -o file:test_ascii.inprogress -c RC4 -k base64:$key > /dev/null
./joelcrypto --decrypt -i file:test_ascii.inprogress -o file:test_ascii.end -c RC4 -k base64:$key > /dev/null
check_result "RC4 cipher" "test_ascii.txt" "test_ascii.end"

iv="qRA67ZlOFFnJj8cRTEt2hw=="

keysizes=(128 192 256)
modes=(ECB CBC OFB CFB CTR)
for b in ${keysizes[@]}
do
	for m in ${modes[@]}
	do
		./joelcrypto --encrypt -i file:test_ascii.txt -o file:test_ascii.inprogress -c AES:$b:$m -k base64:$key -iv base64:$iv > /dev/null
		./joelcrypto --decrypt -i file:test_ascii.inprogress -o file:test_ascii.end -c AES:$b:$m -k base64:$key -iv base64:$iv > /dev/null
		check_result "AES:$b:$m cipher" "test_ascii.txt" "test_ascii.end"
	done
done

rm test_alph.inprogress
rm test_ascii.inprogress
rm test_alph.end
rm test_ascii.end

echo "Tests completed"
read -n 1 -p "Press any key to continue..."
exit