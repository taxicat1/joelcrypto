#ifndef ALPH__CAESER_H
#define ALPH__CAESER_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#include "util.h"
#include "buffered_container.h"
#include "alph/util.h"

inline bool shift_keycheck(const byte* key, const size_t key_len) {
	// TODO
	return false;
}

void shift(buffered_container* input, buffered_container* output, 
	const int amt, const crypto_op operation) {
	
	unsigned int i = 0;
	switch (operation) {
			
		case ENCRYPT:
			while (i < input->buffer_len) {
				byte c = input->buffer[i];
				bool original_is_lower = is_lower(c);
				
				if (original_is_lower) {
					// Character is a lowercase letter
					// Adjust to uppercase
					c = to_upper(c);
				}
				
				if (is_upper(c)) {
					// Encrypt character of input text
					c += amt;
					
					// Wrap back around to valid range by repeatedly subtracting 26
					// Technically, the 26 should be ('Z' - 'A' + 1)
					while (c > 'Z') {
						c -= 26;
					}
					
					while (c < 'A') {
						c += 26;
					}
					
					if (original_is_lower) {
						c = to_lower(c);
					}
				}
				
				bc_write_byte(output, c);
				
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
				
				if (original_is_lower) {
					// Character is a lowercase letter
					// Adjust to uppercase
					c = to_upper(c);
				}
				
				if (is_upper(c)) {
					// Encrypt character of input text
					c -= amt;
					
					// Wrap back around to valid range by repeatedly subtracting 26
					// Technically, the 26 should be ('Z' - 'A' + 1)
					while (c < 'A') {
						c += 26;
					}
					
					while (c > 'Z') {
						c -= 26;
					}
					
					if (original_is_lower) {
						c = to_lower(c);
					}
				}
				
				bc_write_byte(output, c);
				
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

void caesar(buffered_container* input, buffered_container* output, const crypto_op operation) {
	shift(input, output, 3, operation);	
}

#endif