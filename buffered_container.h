#ifndef BUFFERED_CONTAINER_H
#define BUFFERED_CONTAINER_H

#define BUFFER_SIZE 4096
#define CHUNK_SIZE 6
#define MAX_FLUSH_SIZE (int)(BUFFER_SIZE / CHUNK_SIZE) * CHUNK_SIZE // 4092

#define OUTPUT_FILE "w+"
#define INPUT_FILE "r"
#define NO_FILE ""

#define PRINT_HEX 0
#define PRINT_TEXT 1
#define NO_PRINT 2
#define PRINT_BASE64 3

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "types.h"

typedef struct {
	byte buffer[BUFFER_SIZE];
	size_t buffer_len;
	FILE* fd;
	unsigned int pf;
} buffered_container;

buffered_container* bc_new(unsigned int printformat) {
	buffered_container* bc = (buffered_container*)malloc(sizeof(buffered_container));
	bc->buffer_len = 0;
	bc->fd = NULL;
	bc->pf = printformat;
	return bc;
}

buffered_container* bc_from_str(const char* str, unsigned int printformat) {
	assert(str != NULL);
	
	size_t len = strlen(str);
	if (len > BUFFER_SIZE) {
		printf("Error: input as a string literal must be less than %d bytes. For longer inputs, use a file instead.\n", BUFFER_SIZE);
		exit(1);
	}
	
	buffered_container* bc = (buffered_container*)malloc(sizeof(buffered_container));
	memcpy(bc->buffer, str, len);
	bc->buffer_len = len;
	bc->fd = NULL;
	bc->pf = printformat;
	return bc;
}

int bc_rnext(buffered_container* src) {
	if (src->fd == NULL) {
		return 0;
	}
	
	src->buffer_len = fread(src->buffer, 1, BUFFER_SIZE, src->fd);
	return src->buffer_len;
}

buffered_container* bc_from_file(const char* fname, const char* mode, unsigned int printformat) {
	buffered_container* bc = (buffered_container*)malloc(sizeof(buffered_container));
	bc->fd = fopen(fname, mode);
	if (bc->fd == NULL) {
		perror("Error opening file");
		exit(1);
	}
	
	if (mode == INPUT_FILE) {
		int read = bc_rnext(bc);
		if (ferror(bc->fd) != 0) {
			perror("File read error");
			exit(1);
		}
	}
	
	bc->pf = printformat;
	return bc;
}

buffered_container* bc_from_buffer(const byte* buffer, const size_t bufferlen, unsigned int printformat) {
	assert(buffer != NULL);
	
	if (bufferlen > BUFFER_SIZE) {
		printf("Error: input as a buffer literal must be less than %d bytes. For longer inputs, use a file instead.\n", BUFFER_SIZE);
		exit(1);
	}
	
	buffered_container* bc = (buffered_container*)malloc(sizeof(buffered_container));
	memcpy(bc->buffer, buffer, bufferlen);
	bc->buffer_len = bufferlen;
	bc->fd = NULL;
	bc->pf = printformat;
	return bc;
}

void bc_fopen(buffered_container* bc, const char* fname, const char* mode) {
	bc->fd = fopen(fname, mode);
	if (bc->fd == NULL) {
		perror("Error opening file");
		exit(1);
	}
	
	if (mode == INPUT_FILE) {
		bc_rnext(bc);
	}
}

void bc_fclose(buffered_container* bc) {
	if (bc->fd != NULL) {
		fclose(bc->fd);
	}
}

size_t bc_extendbuffer(buffered_container* bc, unsigned int amt) {
	unsigned int start = bc->buffer_len;
	
	if (bc->buffer_len + amt > BUFFER_SIZE) {
		bc->buffer_len = BUFFER_SIZE;
	} else {
		bc->buffer_len += amt;
	}
	
	size_t size = bc->buffer_len - start;
	if (size > 0) {
		memset(&(bc->buffer[start]), 0, size * sizeof(byte));
	}
	
	return size;
}

void bc_printcontents(buffered_container* bc) {
	switch(bc->pf) {
		case PRINT_HEX:
			print_hex(bc->buffer, bc->buffer_len);
			break;
			
		case PRINT_TEXT:
			for (unsigned int i = 0; i < bc->buffer_len; i++) {
				printf("%c", bc->buffer[i]);
			}
			
			break;
			
		case PRINT_BASE64:
			print_base64(bc->buffer, bc->buffer_len);
			break;
			
		case NO_PRINT:
			return;
	}
	
	fflush(stdout);
}

void bc_flush(buffered_container* bc) {
	if (bc->fd == NULL) {
		bc_printcontents(bc);
	} else {
		size_t s = fwrite(bc->buffer, 1, bc->buffer_len, bc->fd);
		if (s != bc->buffer_len) {
			perror("File writing error");
			exit(1);
		}
		
		fflush(bc->fd);
	}
	
	bc->buffer_len = 0;
}

void bc_write(buffered_container* bc, const byte* data, const size_t data_len) {
	
	size_t data_remaining = data_len;
	unsigned int data_pointer = 0;
	
	while (data_remaining > 0) {
		// Check if there is free space in the buffer
		if (bc->buffer_len < MAX_FLUSH_SIZE) {
			
			// We want the data to be flushed on a chunk edge,
			// determine the maximum number of bytes we can copy 
			// into the buffer and still achieve that
			size_t target_size = bc->buffer_len + data_remaining;
			
			if (target_size > BUFFER_SIZE) {
				target_size = MAX_FLUSH_SIZE;
			}
			
			// We have our target size, compute how many bytes we can
			// copy from the input data
			size_t copy_bytes = target_size - bc->buffer_len;
			
			
			if (copy_bytes > 0) {
				memcpy(&bc->buffer[bc->buffer_len], &data[data_pointer], copy_bytes);
				bc->buffer_len += copy_bytes;
				data_pointer += copy_bytes;
				data_remaining -= copy_bytes;
			}
		}
		
		// The buffer is now full up to MAX_FLUSH_SIZE, or the end of the data
		size_t extra_bytes = 0;
		
		// Truncate data and save how much we truncated, if applicable
		if (bc->buffer_len > MAX_FLUSH_SIZE) {
			extra_bytes = bc->buffer_len - MAX_FLUSH_SIZE;
			bc->buffer_len = MAX_FLUSH_SIZE;
		}
		
		if (bc->buffer_len == MAX_FLUSH_SIZE) {
			bc_flush(bc);
		}
		
		// Move extra bytes, if any, to beginning
		if (extra_bytes > 0) {
			bc->buffer_len = extra_bytes;
			memmove(bc->buffer, &bc->buffer[MAX_FLUSH_SIZE], extra_bytes);
		}
	}
}

#endif