#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

#define true 1
#define false 0

typedef unsigned char bool;

typedef unsigned char byte;

enum crypto_op { ENCRYPT, DECRYPT };
typedef enum crypto_op crypto_op;

enum cipher_t { VIGENERE, CAESAR, SHIFT, AES, RC4 };
typedef enum cipher_t cipher_t;

inline void* clone_buffer(const void* src_buff, size_t size) {
	void* dst_buff = malloc(size);
	assert(dst_buff != NULL);	
	memcpy(dst_buff, src_buff, size);
	return dst_buff;
}

inline void swap(byte* a, byte* b) {
	byte temp = *a;
    *a = *b;
    *b = temp;
}

inline bool is_power_2(unsigned int num) {
	return num && !(num & (num - 1));
}

inline void debug_byte_r(const byte* buffer, const unsigned int len) {
	printf("[");
	for (unsigned int i = 0; i < len; i++) {
		if (i + 1 == len) {
			printf("%02x]\n", buffer[i]);
		} else {
			printf("%02x, ", buffer[i]);
		}
	}
	
	fflush(stdout);
}

#endif