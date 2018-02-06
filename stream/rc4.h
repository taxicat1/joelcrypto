#ifndef STREAM__RC4_H
#define STREAM__RC4_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#include "util.h"
#include "buffered_container.h"

void rc4(buffered_container* input, buffered_container* output, 
	const byte* key, const size_t key_len, const crypto_op operation) {
	
	// Allocate and set up state buffer
	byte* S = (byte*)malloc(256);
	assert(S != NULL);
	
	unsigned short j, i;
	
	switch(operation) {
		case ENCRYPT:
		case DECRYPT:
		
			for (i = 0; i < 256; i++) {
				S[i] = i;
			}
			
			// RC4 key schedule
			j = 0;
			for (i = 0; i < 256; i++) {
				j = (j + S[i] + key[i % key_len]) % 256;
				swap(&S[i], &S[j]);
			}
			
			// Stream encryption
			j = 0;
			i = 0;
			byte K;
			
			unsigned int p = 0;
			while (p < input->buffer_len) {
				i = (i + 1) % 256;
				j = (j + S[i]) % 256;
				swap(&S[i], &S[j]);
				
				K = S[(S[i] + S[j]) % 256];
				
				bc_write_byte(output, input->buffer[p] ^ K);
				
				p++;
				// Execute this check on the last loop before we would finish
				if (p == input->buffer_len) {
					if (bc_rnext(input) != 0) {
						// There is more data! Reset iterator
						p = 0;
					}
				}
			}
			
			free(S);
			bc_flush(output);
			break;
			
		default:
			printf("Error: Unsupported operation: '%d'\n", operation);
			exit(1);
	}
}

#endif