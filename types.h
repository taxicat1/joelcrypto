#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "util.h"
#include "alph/util.h"

const char base64_lookup[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void print_base64(const byte* buffer, const size_t buffer_len) {
	unsigned int iterations = ((int)(buffer_len / 3) * 3);
	unsigned int extra_chars = buffer_len - iterations;
	
	byte b1, b2, b3;
	
	for (unsigned int i = 0; i < iterations; i += 3) {
		
		b1 = buffer[i];
		b2 = buffer[i+1];
		b3 = buffer[i+2];
		
		printf("%c", base64_lookup[ b1 >> 2 ]);
		printf("%c", base64_lookup[ ((b1 << 4) & 63) | (b2 >> 4) ]);
		printf("%c", base64_lookup[ ((b2 << 2) & 63) | (b3 >> 6) ]);
		printf("%c", base64_lookup[ b3 & 63 ]);
	}
	
	if (extra_chars == 1) {
		b1 = buffer[buffer_len - 1];
		printf("%c", base64_lookup[ b1 >> 2 ]);
		printf("%c==", base64_lookup[(b1 << 4) & 63]);
	}
	
	if (extra_chars == 2) {
		
		b1 = buffer[buffer_len - 2];
		b2 = buffer[buffer_len - 1];
		
		printf("%c", base64_lookup[ b1 >> 2 ]);
		printf("%c", base64_lookup[ ((b1 << 4) & 63) | (b2 >> 4) ]);
		printf("%c=", base64_lookup[ (b2 << 2) & 63 ]);
	}
}

int base64_value(char);
inline int base64_value(char c) {
	
	if (is_upper(c)) {
		return c - 'A';
	} else if (is_lower(c)) {
		return c - 'a' + 26;
	} else if (isdigit(c)) {
		return c - '0' + 52;
	} else if (c == '+') {
		return 62;
	} else if (c == '/') {
		return 63;
	}
	
	// =
	return -1;
}

int get_base64_size(char* str) {
	size_t str_len = strlen(str);
	
	if (str_len % 4 != 0) {
		return -1;
	}
	
	if (str[str_len - 2] == '=') {
		if (str[str_len - 1] == '=') {
			// Ends with == (two less bytes)
			return ((str_len / 4) * 3) - 2;
		} else {
			// Ends with =_, invalid
			return -1;
		}
	} else if (str[str_len - 1] == '=') {
		// Ends with = (one less byte)
		return ((str_len / 4) * 3) - 1;
	} else {
		// No padding
		return (str_len / 4) * 3;
	}
}

byte* get_base64_bytes(char* str) {
	size_t str_len = strlen(str);
	
	int num_bytes = get_base64_size(str);
	if (num_bytes == -1) {
		return NULL;
	}
	
	for (unsigned int i = 0; i < str_len; i++) {
		
		// Check for invalid characters
		if (
			!is_upper(str[i]) &&
			!is_lower(str[i]) &&
			!isdigit(str[i]) &&
			!(str[i] == '/') &&
			!(str[i] == '+') &&
			!(str[i] == '=')
		) {
			return NULL;
		}
		
		if (str[i] == '=' && i + 3 <= str_len) {
			return NULL;
		}
	}
	
	byte* result = (byte*)malloc(num_bytes * sizeof(byte));
	
	unsigned int byte_count = 0;
	for (unsigned int i = 0; i < str_len; i += 4) {
		
		int v1 = base64_value(str[i]);
		int v2 = base64_value(str[i+1]);
		int v3 = base64_value(str[i+2]);
		int v4 = base64_value(str[i+3]);
		
		result[byte_count++] = ((v1 << 2) & 0xFF) | (v2 >> 4);
		
		if (v3 == -1 && v4 == -1) {
			break;
		}
		
		result[byte_count++] = ((v2 << 4) & 0xFF) | (v3 >> 2);
		
		if (v4 == -1) {
			break;
		}
		
		result[byte_count++] = ((v3 << 6) & 0xFF) | v4;
	}
	
	return result;
}


void print_hex(const byte*, const size_t);
inline void print_hex(const byte* buffer, const size_t buffer_len) {
	for (unsigned int i = 0; i < buffer_len; i++) {
		printf("%0x", buffer[i]);
	}
}

unsigned int get_hex_size(const unsigned int chars) {
	const unsigned int HEX_CHARS_PER_BYTE = 2;
	unsigned int num_bytes = chars / HEX_CHARS_PER_BYTE;
	if (chars % HEX_CHARS_PER_BYTE != 0) {
		num_bytes++;
	}
	
	return num_bytes;
}


byte* get_hex_bytes(const char* str) {
	unsigned int len = strlen(str);
	
	unsigned int num_bytes = get_hex_size(len);
	byte* result = (byte*)malloc(num_bytes);
	int current_char = len - 1;
	
	for (int i = num_bytes - 1; i >= 0; i--) {
		
		char c0, c1;
		unsigned char diff;
		
		if (current_char == 0) {
			c1 = str[current_char];
			c0 = '0'; // Padded 0 on left end of string
		} else {
			c1 = str[current_char--];
			c0 = str[current_char--];
		}
		
		// Handle first letter
		if (c0 <= 'F' && c0 >= 'A') {
			diff = 'A' - 10;
		} else if (c0 <= 'f' && c0 >= 'a') {
			diff = 'a' - 10;
		} else if (c0 <= '9' && c0 >= '0') {
			diff = '0' - 0;
		} else {
			// Invalid!
			free(result);
			return NULL;
		}
		
		// Set upper block
		result[i] = (c0 - diff) << 4;
	
		// Handle second letter
		if (c1 <= 'F' && c1 >= 'A') {
			diff = 'A' - 10;
		} else if (c1 <= 'f' && c1 >= 'a') {
			diff = 'a' - 10;
		} else if (c1 <= '9' && c1 >= '0') {
			diff = '0' - 0;
		} else {
			// Invalid!
			free(result);
			return NULL;
		}
		
		// Set lower block
		result[i] += c1 - diff; 
	}
	
	return result;
}

#endif