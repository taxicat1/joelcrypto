#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#define KEYWORD_SEPARATOR ':'
#define MAX_KEYWORD_STACK 3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "types.h"
#include "buffered_container.h"

inline void print_help_msg() {
	printf("\
    joelcrypto\n\
\n\
  General purpose encryption software.\n\
\n\
* Data input (plaintext or ciphertext)\n\
\n\
    -i, --input     FILE:<filename>\n\
                    TEXT:<ascii text>\n\
                    HEX:<hexadecimal>\n\
                    BASE64:<base64>\n\
\n\
\n\
* Data output (plaintext or ciphertext)\n\
\n\
    -o, --output    FILE:<filename>\n\
                    TEXT   (will output to stdout)\n\
                    HEX    (will output to stdout)\n\
                    BASE64 (will output to stdout)\n\
\n\
\n\
* Cipher selection\n\
\n\
    -c, --cipher    VIGENERE      Vigenere cipher. Accepts text key.\n\
                    CAESAR        Alphabetic shift by 3. Accepts no key.\n\
                    SHIFT         Arbitrary alphabetic shift. Accepts\n\
                                  integer key as text.\n\
\n\
                    RC4           RC4 Stream cipher. Accepts arbitrary size\n\
                                  key of any kind up to 2048 bits.\n\
\n\
                    AES:128:___   AES with a 128 bit key.\n\
                    AES:192:___   AES with a 192 bit key.\n\
                    AES:256:___   AES with a 256 bit key.\n\
\n\
                    AES:___:ECB   AES in Electronic Codebook mode.\n\
                    AES:___:CBC   AES in Cipher Block Chain mode. Requires IV.\n\
                    AES:___:OFB   AES in Output Feedback mode. Requires IV.\n\
                    AES:___:CFB   AES in Cipher Feedback mode. Requires IV.\n\
                    AES:___:CTR   AES in Counter mode.  Requires IV.\n\
\n\
\n\
* Initialization vector (IV). Not required for many ciphers. For encryption,\n\
  an IV can be automatically generated.\n\
\n\
    -iv, --initialization-vector\n\
                    GENERATE:FILE:<filename>\n\
                    GENERATE:TEXT   (will output to stdout)\n\
                    GENERATE:HEX    (will output to stdout)\n\
                    GENERATE:BASE64 (will output to stdout)\n\
\n\
                    FILE:<filename>\n\
                    TEXT:<ascii text>\n\
                    HEX:<hexadecimal>\n\
                    BASE64:<base64>\n\
\n\
\n\
* Encryption key. Required for most ciphers.\n\
\n\
    -k, --key       FILE:<filename>\n\
                    TEXT:<ascii text>\n\
                    HEX:<hexadecimal>\n\
                    BASE64:<base64>\n\
\n\
\n\
* Operation. Select encryption or decryption.\n\
\n\
    --encrypt\n\
    --decrypt\n\
");
	
	exit(0);
}

char** split_string(char* string) {
	unsigned int len = strlen(string);
	
	if (len == 0) {
		printf(ERROR_EMPTY_ARGUMENT);
		exit(1);
	}
	
	// Count how many characters go by until we see a separator
	int lengths[MAX_KEYWORD_STACK] = { 0 };
	
	unsigned int len_cnt = 0;
	
	// The tag is a copy of the first 7 bytes of the string (+terminator for 8)
	// It is used to detect if there is a literal tag, such as TEXT: or FILE:
	char tag[8];
	tag[0] = string[0];
	
	for (unsigned int i = 0; i < len; i++) {
		//printf("(1) i=%d, string[i]=%c, len_cnt=%d, lengths[0]=%d\n", i, string[i], len_cnt, lengths[0]);
		if (string[i] == KEYWORD_SEPARATOR) {
			len_cnt++;
		} else {
			
			if (len_cnt == MAX_KEYWORD_STACK) {
				printf(ERROR_INVALID_ARGUMENT, string);
				exit(1);
			}
			
			lengths[len_cnt]++;
			
			if (i < 6 && len > i + 1) {
				tag[i + 1] = string[i + 1];
				tag[i + 2] = '\0'; // Don't forget to wear your null terminator
			}
			
			
			if (i == 2) {
				if (strcasecmp(tag, "HEX:") == 0) {
					// Tag found, abort rest of counting
					lengths[++len_cnt] = len - i - 1;
					break;
				}
			}
			
			
			if (i == 3) {
				if (
					strcasecmp(tag, "TEXT:") == 0 ||
					strcasecmp(tag, "FILE:") == 0
				) {
					// Tag found, abort rest of counting
					lengths[++len_cnt] = len - i;
					break;
				}
			}
			
			
			if (i == 5) {
				if (strcasecmp(tag, "BASE64:") == 0) {
					// Tag found, abort rest of counting
					lengths[++len_cnt] = len - i;
					break;
				}
			}
			
		}
	}
	
	// Correct the len_cnt for trailing delimiters by verifying each recorded length
	len_cnt = 0;
	for (unsigned int i = 0; i < MAX_KEYWORD_STACK; i++) {
	    if (lengths[i] != 0) {
	        len_cnt++;
	    }
	}
	
	// Allocate X pointers, one for every run we found between separators
	char** result = (char**)malloc(sizeof(char*) * MAX_KEYWORD_STACK);
	for (unsigned int i = 0; i < MAX_KEYWORD_STACK; i++) {
		result[i] = NULL;
	}
	
	for (unsigned int i = 0; i < len_cnt; i++) {
	    
		// Allocate space for keywords, +1 for the null terminators
		result[i] = (char*)malloc(lengths[i] + 1 * sizeof(char));
		
		// Copy string into buffers
		
		// Compute the offset from the start by summing up previous lengths
		unsigned int offset = 0;
		for (unsigned int j = 0; j < i; j++) {
		    offset += lengths[j];
		}
		
		memcpy(result[i], &(string[offset + i]), lengths[i]);
		
		// Don't forget to wear your null terminator
		result[i][lengths[i]] = '\0';
	}
	
	return result;
}

buffered_container* parse_keywords_to_output_bc(char* keywords) {
	
	char** keywords_split = split_string(keywords);
	
	if (keywords_split[0] == NULL) {
		printf(ERROR_EMPTY_ARGUMENT);
		exit(1);
	}
	
	// Valid keywords here: FILE, TEXT, HEX, BASE64
	if (strcasecmp(keywords_split[0], "FILE") == 0) {
		
		if (keywords_split[1] == NULL || strlen(keywords_split[1]) == 0) {
			printf(ERROR_NO_FILE_SPECIFIED);
			exit(1);
		}
		
		if (keywords_split[2] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[2], keywords);
		}
	
		return bc_from_file(keywords_split[1], OUTPUT_FILE, NO_PRINT);
	}
	
	// Create a new output buffer with PRINT_TEXT as its output method
	if (strcasecmp(keywords_split[0], "TEXT") == 0) {
		
		if (keywords_split[1] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[1], keywords);
		}
		
		if (keywords_split[2] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[2], keywords);
		}
		
		return bc_new(PRINT_TEXT);
	}
	
	// Create a new output buffer with PRINT_HEX as its output method
	if (strcasecmp(keywords_split[0], "HEX") == 0) {
		
		if (keywords_split[1] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[1], keywords);
		}
		
		if (keywords_split[2] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[2], keywords);
		}
		
		return bc_new(PRINT_HEX);
	}
	
	// Create a new output buffer with PRINT_BASE64 as its output method
	if (strcasecmp(keywords_split[0], "BASE64") == 0) {
		
		if (keywords_split[1] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[1], keywords);
		}
		
		if (keywords_split[2] != NULL) {
			printf(WARNING_EXTRA_DATA, keywords_split[2], keywords);
		}
		
		return bc_new(PRINT_BASE64);
	}
	
	printf(ERROR_INVALID_ARGUMENT, keywords);
	exit(1);
}
	
buffered_container* parse_keywords_to_input_bc(char* keywords) {
	
	char** keywords_split = split_string(keywords);
	
	if (
		keywords_split[0] == NULL || 
		keywords_split[1] == NULL
	) {
		printf(ERROR_INVALID_ARGUMENT, keywords);
		exit(1);
	}
	
	
	// Valid keywords here: FILE, TEXT, HEX, BASE64
	if (strcasecmp(keywords_split[0], "FILE") == 0) {		
		return bc_from_file(keywords_split[1], INPUT_FILE, NO_PRINT);
	}
	
	
	if (strcasecmp(keywords_split[0], "TEXT") == 0) {		
		return bc_from_str(keywords_split[1], NO_PRINT);
	}
	
	
	if (strcasecmp(keywords_split[0], "HEX") == 0) {
		
		size_t buffersize = get_hex_size(strlen(keywords_split[1]));
		byte* buffer = get_hex_bytes(keywords_split[1]);
		
		if (buffer == NULL) {
			printf(ERROR_HEX_INVALID);
			exit(1);
		}
		
		return bc_from_buffer(buffer, buffersize, NO_PRINT);
	}
	
	
	if (strcasecmp(keywords_split[0], "BASE64") == 0) {
		
		size_t buffersize = get_base64_size(keywords_split[1]);
		byte* buffer = get_base64_bytes(keywords_split[1]);
		
		if (buffer == NULL) {
			printf(ERROR_BASE64_INVALID);
			exit(1);
		}		
		
		return bc_from_buffer(buffer, buffersize, NO_PRINT);
	}
	
	printf(ERROR_INVALID_ARGUMENT, keywords);
	exit(1);
}

#endif