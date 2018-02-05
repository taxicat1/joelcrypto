#ifndef ALPH__VIGENERE_H
#define ALPH__VIGENERE_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#include "util.h"
#include "buffered_container.h"
#include "alph/util.h"

bool vigenere_keycheck(const byte* key, const size_t key_len) {
	// Input text can be invalid as that character is
	// skipped, but the key cannot
	byte* key_cpy = (byte*)clone_buffer(key, key_len);
	
	for (unsigned int i = 0; i < key_len; i++) {
		if (is_lower(key_cpy[i])) {
			// Character is a lowercase letter
			// Adjust to uppercase
			key_cpy[i] = to_upper(key_cpy[i]);
		}
		
		if (!is_upper(key_cpy[i])) {
			// Character (after case correction) is outside range
			free(key_cpy);
			return false;
		}
	}
	
	free(key_cpy);
	return true;
}

byte* vigenere(buffered_container* input, buffered_container* output, 
	const byte* key, const size_t key_len, const crypto_op operation) {
	
	output->buffer_len = 0;

	unsigned int i = 0;
	unsigned int key_i = 0;
	
	switch (operation) {
		case ENCRYPT:
			while (i < input->buffer_len) {
				byte c = input->buffer[i];
				
				bool original_is_lower = is_lower(c);
				
				if (is_lower(c)) {
					// Character is a lowercase letter
					// Adjust to uppercase
					c = to_upper(c);
				}
				
				
				if (is_upper(c)) {
					// Encrypt character of input text
					// Subtracting 'A' from the key to normalize A to 0 instead 
					// of the ASCII value of 65
					byte k = key[key_i % key_len];
					k = to_upper(k);
					key_i++;
					
					c += k - 'A';
					
					// Wrap back around to valid range by repeatedly subtracting 26
					// Technically, the 26 should be ('Z' - 'A' + 1)
					while (c > 'Z') {
						c -= 26;
					}
					
					if (original_is_lower) {
						c = to_lower(c);
					}
				}
				
				bc_write(output, &c, 1);
				
				i++;
				if (i == input->buffer_len) {
					if (bc_rnext(input) != 0) {
						// There is more data! Reset i to 0
						i = 0;
					} // Else there is no more data, we can finish
				}
			}
			
			bc_flush(output);
			break;
			
			
		case DECRYPT:
			while (i < input->buffer_len) {
				byte c = input->buffer[i];
				
				bool original_is_lower = is_lower(c);
				
				if (is_lower(c)) {
					// Character is a lowercase letter
					// Adjust to uppercase
					c = to_upper(c);
				}
				
				
				if (is_upper(c)) {
					// Decrypt character of input text
					// Subtracting 'A' from the key to normalize A to 0 instead 
					// of the ASCII value of 65
					byte k = key[key_i % key_len];
					k = to_upper(k);
					key_i++;
					
					c -= k - 'A';
					
					// Wrap back around to valid range by repeatedly subtracting 26
					// Technically, the 26 should be ('Z' - 'A' + 1)
					while (c < 'A') {
						c += 26;
					}
					
					if (original_is_lower) {
						c = to_lower(c);
					}
				}
				
				bc_write(output, &c, 1);
				
				i++;
				if (i == input->buffer_len) {
					if (bc_rnext(input) != 0) {
						// There is more data! Reset i to 0
						i = 0;
					} // Else there is no more data, we can finish
				}
			}
			
			bc_flush(output);
			break;
		
		
		default:
			printf("Error: Unsupported operation: '%d'\n", operation);
			exit(1);
	}
}

#endif