#ifndef BLOCK__UTIL_H
#define BLOCK__UTIL_H

#define WARNING_KEY_INCORRECT "Warning: padding was not correct on decrypted data, key was most likely incorrect.\n"
#define PADDING_UNKNOWN -1

#include "util.h"

enum cmode_t { ECB, CBC, CFB, OFB, CTR };
typedef enum cmode_t cmode_t;

typedef void (*block_func)(byte*, const size_t, const byte*, const size_t);

inline void xor_buffer(byte* src, const byte* out, size_t len) {
	for (unsigned int i = 0; i < len; i++) {
		src[i] ^= out[i];
	}
}

inline void increment_buffer(byte* buff, const size_t buff_len) {
	int i = buff_len - 1;
	do {
	    buff[i] = (buff[i] + 1) % 256;
	    i--;
	} while (buff[i + 1] == 0 && i >= 0);
}

bool try_padding(buffered_container* bc, const size_t block_size) {
	// Padding can always be done if the buffer is not full, as long as the block
	// size we are padding to is a power of two, which is very common.
	
	if (bc->buffer_len < BUFFER_SIZE) {
		
		// Floor divide, add one, multiple back, then subtract original length
		size_t padding_len = (((int)(bc->buffer_len / block_size) + 1) * block_size) - bc->buffer_len;
		byte pad_byte = (byte)padding_len;
		
		unsigned int first_pad_byte = bc->buffer_len;
		unsigned int new_bytes = bc_extendbuffer(bc, padding_len);
		
		assert(new_bytes == padding_len);
		
		for (unsigned int i = 0; i < new_bytes; i++) {
			bc->buffer[first_pad_byte + i] = pad_byte;
		}
		
		return true;
	}
	
	return false;
}

void ECB_encrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const size_t block_size, const byte* key, const size_t key_size) {
	
	assert(is_power_2(block_size));
	
	// Padding using PKCS5
	bool padded = try_padding(input, block_size);
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			encryptor(block, block_size, key, key_size);
			bc_write(output, block, block_size);
		}
		
		i++;
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
				
				// Fresh data loaded, try to pad it if we have not done padding
				if (!padded) {
					padded = try_padding(input, block_size);
				}
			} // Else there is no more data, we can finish
			
			// This is a special case, where the data ends on the edge of a buffer
			// In this case, we need block_size bytes of padding
			if (input->buffer_len == 0 && !padded) {
				padded = try_padding(input, block_size);
				assert(padded);
				
				// Set the iterator back to zero so it will encrypt the padding
				i = 0;
			}
		}
	}
	
	free(block);
	bc_flush(output);
}

void ECB_decrypt(block_func decryptor, buffered_container* input, buffered_container* output,
	const size_t block_size, const byte* key, const size_t key_size) {
	
	assert(is_power_2(block_size));
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			decryptor(block, block_size, key, key_size);
			bc_write(output, block, block_size);
		}
		
		i++;
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
			}
		}
	}
	
	free(block);
	
	if (i % block_size != 0) {
		printf(WARNING_DATA_NOT_BLOCKED);
	} else {	
		// Remove padding
		byte padding = output->buffer[output->buffer_len - 1];
		
		// Check if padding is valid, first by comparing the
		// pad bytes with the block size
		if (padding > block_size) {
			printf(WARNING_KEY_INCORRECT);
		} else {
			// Next padding check, verify bytes prior to the padding 
			unsigned int k;
			for (k = 0; k < padding; k++) {
				int offset = output->buffer_len - 1 - k;
				
				if (output->buffer[offset] != padding) {
					printf(WARNING_KEY_INCORRECT);
					break;
				}
			}
			
			// Padding check cleared, remove it
			if (k == padding) {
				output->buffer_len -= padding;
			}
		}
	}
	
	bc_flush(output);
}

void CBC_encrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	assert(is_power_2(block_size));
	
	// Padding using PKCS5
	bool padded = try_padding(input, block_size);
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	// Set up IV
	byte* previous_block = clone_buffer(iv, iv_size);
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			
			// XOR previous block (or IV) as per CBC
			xor_buffer(block, previous_block, block_size);
			
			// Do encryption
			encryptor(block, block_size, key, key_size);
			
			// Copy current block into previous block for next round
			memcpy(previous_block, block, block_size);
			
			// Write to output buffer
			bc_write(output, block, block_size);
		}
		
		i++;
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
				
				// Fresh data loaded, try to pad it if we have not done padding
				if (!padded) {
					padded = try_padding(input, block_size);
				}
			} // Else there is no more data, we can finish
			
			// This is a special case, where the data ends on the edge of a buffer
			// In this case, we need block_size bytes of padding
			if (input->buffer_len == 0 && !padded) {
				padded = try_padding(input, block_size);
				assert(padded);
				
				// Set the iterator back to zero so it will encrypt the padding
				i = 0;
			}
		}
	}
	
	free(block);
	free(previous_block);
	bc_flush(output);
}

void CBC_decrypt(block_func decryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	assert(is_power_2(block_size));
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	// Set up IV
	byte* previous_block = clone_buffer(iv, iv_size);
	byte* ct_block = (byte*)malloc(block_size * sizeof(byte));
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			
			// Copy of ciphertext
			memcpy(ct_block, block, block_size);
			
			// Do decryption
			decryptor(block, block_size, key, key_size);
			xor_buffer(block, previous_block, block_size);
			
			// Make ciphertext copied before into the previous block for next round
			memcpy(previous_block, ct_block, block_size);
			
			// Write to output buffer
			bc_write(output, block, block_size);
		}
		
		i++;
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
			}
		}
	}
	
	free(block);
	free(ct_block);
	free(previous_block);
	
	if (i % block_size != 0) {
		printf(WARNING_DATA_NOT_BLOCKED);
	} else {
		// Remove padding
		byte padding = output->buffer[output->buffer_len - 1];
		
		// Check if padding is valid, first by comparing the
		// pad bytes with the block size
		if (padding > block_size) {
			printf(WARNING_KEY_INCORRECT);
		} else {
			// Next padding check, verify bytes prior to the padding 
			unsigned int k;
			for (k = 0; k < padding; k++) {
				int offset = output->buffer_len - 1 - k;
				
				if (output->buffer[offset] != padding) {
					printf(WARNING_KEY_INCORRECT);
					break;
				}
			}
			
			// Padding check cleared, remove it
			if (k == padding) {
				output->buffer_len -= padding;
			}
		}
	}
	
	bc_flush(output);
}


void CFB_encrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	// Set up IV
	byte* previous_block = clone_buffer(iv, iv_size);
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			
			// Do encryption on previous output
			encryptor(previous_block, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(block, previous_block, block_size);
			
			// Copy current block into previous block for next round
			memcpy(previous_block, block, block_size);
			
			// Write to output buffer
			bc_write(output, block, block_size);
		}
		
		i++;
		
		// The final block is encrypted here, this block does not need to be
		// the full block size
		if (i == input->buffer_len && input->buffer_len != BUFFER_SIZE) {
			// Do encryption on previous output
			encryptor(previous_block, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(block, previous_block, i % block_size);
			
			// Write to output buffer
			bc_write(output, block, i % block_size);
		}
		
		// Load next block like normal if the buffer is full
		// Note that if we do this, we will never trigger the above code to 
		// encrypt the final block. But, this doesn't matter as if this happens
		// then clearly the input buffer is a multiple of the block size, and we
		// never need to!
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
			} // Else there is no more data, we can finish
		}
	}
	
	free(block);
	free(previous_block);
	bc_flush(output);
}

void CFB_decrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	// Set up IV
	byte* previous_ct = clone_buffer(iv, iv_size);
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			
			// Do encryption on previous output
			encryptor(previous_ct, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(previous_ct, block, block_size);
			
			// Write to output buffer
			bc_write(output, previous_ct, block_size);
			
			// Copy current block into previous block for next round
			memcpy(previous_ct, block, block_size);
		}
		
		i++;
		
		// The final block is encrypted here, this block does not need to be
		// the full block size
		if (i == input->buffer_len && input->buffer_len != BUFFER_SIZE) {
			// Do encryption on previous output
			encryptor(previous_ct, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(previous_ct, block, i % block_size);
			
			// Write to output buffer
			bc_write(output, previous_ct, i % block_size);
		}
		
		// Load next block like normal if the buffer is full
		// Note that if we do this, we will never trigger the above code to 
		// encrypt the final block. But, this doesn't matter as if this happens
		// then clearly the input buffer is a multiple of the block size, and we
		// never need to!
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
			} // Else there is no more data, we can finish
		}
	}
	
	free(block);
	free(previous_ct);
	bc_flush(output);
}

void OFB_encrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	// Set up IV
	byte* e_output = clone_buffer(iv, iv_size);
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			
			// Do encryption on previous output
			encryptor(e_output, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(block, e_output, block_size);
			
			// Write to output buffer
			bc_write(output, block, block_size);
		}
		
		
		i++;
		
		// The final block is encrypted here, this block does not need to be
		// the full block size
		if (i == input->buffer_len && input->buffer_len != BUFFER_SIZE) {
			// Do encryption on previous output
			encryptor(e_output, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(block, e_output, i % block_size);
			
			// Write to output buffer
			bc_write(output, block, i % block_size);
		}
		
		// Load next block like normal if the buffer is full
		// Note that if we do this, we will never trigger the above code to 
		// encrypt the final block. But, this doesn't matter as if this happens
		// then clearly the input buffer is a multiple of the block size, and we
		// never need to!
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
			} // Else there is no more data, we can finish
		}
	}
	
	free(block);
	free(e_output);
	bc_flush(output);
}

void OFB_decrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	// These are literally identical
	OFB_encrypt(encryptor, input, output, iv, iv_size, block_size, key, key_size);
}

void CTR_encrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	assert(iv_size == block_size);
	
	byte* block = (byte*)malloc(block_size * sizeof(byte));
	
	// Set up IV
	byte* counter = clone_buffer(iv, iv_size);
	byte* counter_cpy = (byte*)malloc(block_size * sizeof(byte));
	
	unsigned int i = 0;
	while (i < input->buffer_len) {
		
		block[i % block_size] = input->buffer[i];
		
		if (i % block_size == block_size - 1) {
			
			// Do encryption on counter
			memcpy(counter_cpy, counter, block_size);
			encryptor(counter_cpy, block_size, key, key_size);
			increment_buffer(counter, iv_size);
			
			// XOR input block with output
			xor_buffer(block, counter_cpy, block_size);
			
			// Write to output buffer
			bc_write(output, block, block_size);
		}
		
		i++;
		
		// The final block is encrypted here, this block does not need to be
		// the full block size
		if (i == input->buffer_len && input->buffer_len != BUFFER_SIZE) {
			// Do encryption on counter
			encryptor(counter, block_size, key, key_size);
			
			// XOR input block with output
			xor_buffer(block, counter, i % block_size);
			
			// Write to output buffer
			//memcpy(&(output->buffer[output->buffer_len]), block, i % block_size);
			//output->buffer_len += i % block_size;
			bc_write(output, block, i % block_size);
		}
		
		// Load next block like normal if the buffer is full
		// Note that if we do this, we will never trigger the above code to 
		// encrypt the final block. But, this doesn't matter as if this happens
		// then clearly the input buffer is a multiple of the block size, and we
		// never need to!
		if (i == input->buffer_len) {
			if (bc_rnext(input) != 0) {
				// There is more data! Reset i to 0
				i = 0;
			} // Else there is no more data, we can finish
		}
	}
	
	free(block);
	free(counter);
	free(counter_cpy);
	bc_flush(output);
}

void CTR_decrypt(block_func encryptor, buffered_container* input, buffered_container* output,
	const byte* iv, const size_t iv_size, const size_t block_size, const byte* key, const size_t key_size) {
	
	// These are also literally identical
	CTR_encrypt(encryptor, input, output, iv, iv_size, block_size, key, key_size);
}
#endif
