#define ERROR_NO_INPUT                "Error: no input provided (-i, --input).\n"
#define ERROR_MULTIPLE_INPUT          "Error: input is multiply defined.\n"
#define ERROR_NO_OUTPUT               "Error: no output provided (-o, --output).\n"
#define ERROR_MULTIPLE_OUTPUT         "Error: output is multiply defined.\n"
#define ERROR_NO_KEY                  "Error: no key provided (-k, --key).\n"
#define ERROR_MULTIPLE_KEY            "Error: key is multiply defined\n"
#define ERROR_NO_IV                   "Error: an IV is required for this cipher mode (-iv, --initialization-vector).\n"
#define ERROR_MULTIPLE_IV             "Error: IV is multiply defined\n"
#define ERROR_CANNOT_GENERATE_IV      "Error: IVs can only be generated while encrypting.\n"
#define ERROR_KEY_INVALID             "Error: key is invalid.\n"
#define ERROR_KEY_INVALID_SIZE        "Error: key is not the correct size (%d bytes instead of %d bytes).\n"
#define ERROR_NO_OPERATION            "Error: no operation provided (--encrypt, --decrypt).\n"
#define ERROR_MULTIPLE_OPERATION      "Error: operation is multiply defined.\n"
#define ERROR_NO_CIPHER               "Error: no cipher provided (-c, --cipher).\n"
#define ERROR_MULTIPLE_CIPHER         "Error: cipher is multiply defined.\n"
#define ERROR_INVALID_CIPHER          "Error: invalid cipher \"%s\".\n"
#define ERROR_MUST_SELECT_CIPHER_KS   "Error: must select a key size for choosen cipher.\n"
#define ERROR_MUST_SELECT_CIPHER_MODE "Error: must select a mode for choosen cipher.\n"
#define ERROR_INVALID_ARGUMENT        "Invalid argument \"%s\".\n"
#define ERROR_EMPTY_ARGUMENT          "Error: zero-length argument is invalid.\n"
#define ERROR_HEX_INVALID             "Error: HEX:<> contains invalid characters.\n"
#define ERROR_BASE64_INVALID          "Error: BASE64:<> is not valid base64. Did you forget padding?\n"
#define ERROR_NO_FILE_SPECIFIED       "Error: no file has been specified in FILE:<>\n"

#define WARNING_IV_NOT_NEEDED         "Warning: an IV is not used by the selected cipher, and will be ignored.\n"
#define WARNING_IV_TOO_LONG           "Warning: IV exceeds 128 bits, only the first 128 bits will be used.\n"
#define WARNING_KEY_NOT_NEEDED        "Warning: the selected cipher does not require a key.\n"
#define WARNING_EXTRA_DATA            "Warning: ignoring extra data \"%s\" in argument \"%s\".\n"
#define WARNING_PADDING_IV            "Warning: the provided IV is too short and will be zero-padded to 128 bits.\n"
#define WARNING_KEY_TRUNCATION        "Warning: the provided key is too long and will be truncated to %d bits.\n"
#define WARNING_KEY_ZERO_PADDING      "Warning: the provided key is too short and will be zero-padded to %d bits.\n"
#define WARNING_DATA_NOT_BLOCKED      "Warning: the provided input data was not a multiple of the block size!\nThe ending bytes were ignored. Did you select the right cipher mode?\n" 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "windows.h"
#include "util.h"
#include "buffered_container.h"
#include "types.h"
#include "alph/util.h"
#include "alph/vigenere.h"
#include "alph/caesar_shift.h"
#include "block/util.h"
#include "block/aes.h"
#include "stream/rc4.h"

#include "arguments.h"
	
int main(int argc, char** argv) {
	printf("\n");
	
	if (argc == 1) {
		print_help_msg();
	}
	
	for (unsigned int i = 0; i < argc; i++) {
		if (
			strcmp(argv[i], "-h") == 0 ||
			strcmp(argv[i], "--help") == 0
		) {
			print_help_msg();
		}
	}
	
	// Default assumptions
	bool input_defined = false,		// If input has been defined
	     output_defined = false,	// If output has been defined
		 operation_defined = false,	// If the operation (encrypt or decrypt) has been defined
		 iv_defined = false,		// If an IV has been defined
		 iv_needed = true,			// If an IV is needed for choosen cipher
		 can_generate_iv = true,	// Cannot generate IV if decrypting, for example
		 will_generate_iv =	false,	// If we will generate an IV for encryption
		 key_needed = true,			// If we need a key for selected cipher
		 key_defined = false,		// If the key has been defined
		 cipher_defined = false;	// If the cipher has been choosen
	
	char* iv_arguments;
	
	buffered_container* input  = NULL;
	buffered_container* output = NULL;
	buffered_container* iv     = NULL;
	buffered_container* key    = NULL;
	
	byte* iv_buffer;
	byte* key_buffer;
	
	size_t iv_len;
	size_t key_len;
	
	unsigned int key_size_bytes;
	bool use_key_size_bytes = false;
	
	cipher_t choosen_cipher;
	cmode_t choosen_mode;
	crypto_op operation;
	
	
	for (unsigned int j = 1; j < argc; j++) {
		
		bool last_arg = j + 1 == argc;
		
		
		// Handle input
		//---------------------------
		if (
			strcmp(argv[j], "-i") == 0 ||
			strcmp(argv[j], "--input") == 0
		) {
			
			if (input_defined) {
				printf(ERROR_MULTIPLE_INPUT);
				return 1;
			}
			
			if (last_arg) {
				printf(ERROR_NO_INPUT);
				return 1;
			}
			
			char* next_arg = argv[++j];
			input = parse_keywords_to_input_bc(next_arg);
			input_defined = true;
			
		}
		//---------------------------
		
		
		
		// Handle output
		//---------------------------
		else if (
			strcmp(argv[j], "-o") == 0 ||
			strcmp(argv[j], "--output") == 0
		) {
			
			if (output_defined) {
				printf(ERROR_MULTIPLE_OUTPUT);
				return 1;
			}
			
			if (last_arg) {
				printf(ERROR_NO_OUTPUT);
				return 1;
			}
			
			char* next_arg = argv[++j];
			output = parse_keywords_to_output_bc(next_arg);
			output_defined = true;
		}
		//---------------------------
		
		
		
		// Handle encrypt operation
		//---------------------------
		else if (
			strcmp(argv[j], "--encrypt") == 0
		) {			
			if (operation_defined) {
				printf(ERROR_MULTIPLE_OPERATION);
				return 1;
			}
			
			operation = ENCRYPT;
			operation_defined = true;
		}
		//---------------------------
		
		
		
		// Handle encrypt operation
		//---------------------------
		else if (
			strcmp(argv[j], "--decrypt") == 0
		) {			
			if (operation_defined) {
				printf(ERROR_MULTIPLE_OPERATION);
				return 1;
			}
			
			can_generate_iv = false;
			if (will_generate_iv) {
				printf(ERROR_CANNOT_GENERATE_IV);
				return 1;
			}
			
			operation = DECRYPT;
			operation_defined = true;
		}
		//---------------------------
		
		
		
		// Handle IV
		//---------------------------
		else if (
			strcmp(argv[j], "-iv") == 0 ||
			strcmp(argv[j], "--initialization-vector") == 0
		) {
			
			if (iv_defined) {
				printf(ERROR_MULTIPLE_IV);
				return 1;
			}
			
			if (!iv_needed) {
				printf(WARNING_IV_NOT_NEEDED);
			}
			
			if (last_arg) {
				printf(ERROR_NO_IV);
				return 1;
			}
			
			char* next_arg = argv[++j];
			
			const char* GEN = "GENERATE:";
			const size_t GENlen = strlen(GEN);
			
			if (strncasecmp(next_arg, GEN, GENlen) == 0) {
				// Argument begins with GENERATE, create an IV
				if (!can_generate_iv) {
					printf(ERROR_CANNOT_GENERATE_IV);
					return 1;
				}
				
				will_generate_iv = true;
				iv_arguments = &next_arg[GENlen];
				
			} else {
				// Otherwise, an IV has been provided
				iv = parse_keywords_to_input_bc(next_arg);
				
				iv_buffer = iv->buffer;
				iv_len = iv->buffer_len;
				if (iv_len > 16) {
					printf(WARNING_IV_TOO_LONG);
				}
				
				if (iv_len < 16) {
					printf(WARNING_PADDING_IV);
				}
			}
			
			iv_defined = true;
		}
		//---------------------------
		
		
		
		// Handle key
		//---------------------------
		else if (
			strcmp(argv[j], "-k") == 0 ||
			strcmp(argv[j], "--key") == 0
		) {
			
			if (key_defined) {
				printf(ERROR_MULTIPLE_KEY);
				return 1;
			}
			
			if (last_arg) {
				printf(ERROR_NO_KEY);
				return 1;
			}
			
			char* next_arg = argv[++j];
			key = parse_keywords_to_input_bc(next_arg);
			
			key_buffer = key->buffer;
			key_len = key->buffer_len;
			
			key_defined = true;
		}
		//---------------------------
		
		
		
		// Handle cipher
		//---------------------------
		else if (
			strcmp(argv[j], "-c") == 0 ||
			strcmp(argv[j], "--cipher") == 0
		) {
			if (cipher_defined) {
				printf(ERROR_MULTIPLE_CIPHER);
				return 1;
			}
			
			if (last_arg) {
				printf(ERROR_NO_CIPHER);
				return 1;
			}
			
			char* next_arg = argv[++j];
			char** cipher_args = split_string(next_arg);
			
			// Vigenere cipher
			//---------------------------
			if (strcasecmp(cipher_args[0], "VIGENERE") == 0) {
				choosen_cipher = VIGENERE;
				iv_needed = false;
				
				if (cipher_args[1] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[1], next_arg);
				}
				
				if (cipher_args[2] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[2], next_arg);
				}
				
			}
			//---------------------------
			
			
			
			// Caesar cipher
			//---------------------------
			else if (strcasecmp(cipher_args[0], "CAESAR") == 0) {
				choosen_cipher = CAESAR;
				iv_needed = false;
				key_needed = false;
				
				if (key_defined) {
					printf(WARNING_KEY_NOT_NEEDED);
				}
				
				if (cipher_args[1] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[1], next_arg);
				}
				
				if (cipher_args[2] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[2], next_arg);
				}
				
			}
			//---------------------------
			
			
			
			// Shift cipher
			//---------------------------
			else if (strcasecmp(cipher_args[0], "SHIFT") == 0) {
				choosen_cipher = SHIFT;
				iv_needed = false;
				
				if (cipher_args[1] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[1], next_arg);
				}
				
				if (cipher_args[2] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[2], next_arg);
				}
				
			}
			//---------------------------
			
			
			
			// RC4 cipher
			//---------------------------
			else if (strcasecmp(cipher_args[0], "RC4") == 0) {
				choosen_cipher = RC4;
				iv_needed = false;
				
				if (cipher_args[1] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[1], next_arg);
				}
				
				if (cipher_args[2] != NULL) {
					printf(WARNING_EXTRA_DATA, cipher_args[2], next_arg);
				}
				
			}
			//---------------------------
			
			
			
			// AES cipher
			//---------------------------
			else if (strcasecmp(cipher_args[0], "AES") == 0) {
				choosen_cipher = AES;
				use_key_size_bytes = true;
				
				// Empty key size
				if (cipher_args[1] == NULL) {
					printf(ERROR_MUST_SELECT_CIPHER_KS);
					exit(1);
				}
			
				// 128 bit keys
				//---------------------------
				if (strcmp(cipher_args[1], "128") == 0) {
					key_size_bytes = 16;
				}
				//---------------------------
				
				
				// 192 bit keys
				//---------------------------
				else if (strcmp(cipher_args[1], "192") == 0) {
					key_size_bytes = 24;
				}
				//---------------------------
				
				
				// 256 bit keys
				//---------------------------
				else if (strcmp(cipher_args[1], "256") == 0) {
					key_size_bytes = 32;
				}
				//---------------------------
				
				
				// Invalid key size
				//---------------------------
				else {
					printf(ERROR_INVALID_ARGUMENT, cipher_args[1]);
					return 1;
				}
				//---------------------------
				
				
				// Empty mode
				if (cipher_args[2] == NULL) {
					printf(ERROR_MUST_SELECT_CIPHER_MODE);
					exit(1);
				}
				
				// ECB mode
				//---------------------------
				if (strcasecmp(cipher_args[2], "ECB") == 0) {
					choosen_mode = ECB;
					iv_needed = false;
				}
				//---------------------------
				
				
				// CBC mode
				//---------------------------
				else if (strcasecmp(cipher_args[2], "CBC") == 0) {
					choosen_mode = CBC;
				}
				//---------------------------
				
				
				// CFB mode
				//---------------------------
				else if (strcasecmp(cipher_args[2], "CFB") == 0) {
					choosen_mode = CFB;
				}
				//---------------------------
				
				
				// OFB mode
				//---------------------------
				else if (strcasecmp(cipher_args[2], "OFB") == 0) {
					choosen_mode = OFB;
				}
				//---------------------------
				
				
				// CTR mode
				//---------------------------
				else if (strcasecmp(cipher_args[2], "CTR") == 0) {
					choosen_mode = CTR;
				}
				//---------------------------
				
				
				// Invalid mode
				//---------------------------
				else {
					printf(ERROR_INVALID_ARGUMENT, cipher_args[2]);
					return 1;
				}
				//---------------------------
			
			
			// Invalid cipher
			//---------------------------
			} else {
				printf(ERROR_INVALID_CIPHER, cipher_args[0]);
				return 1;
			}
			//---------------------------
			
			
			// Check IV status for choosen cipher
			if (!iv_needed && iv_defined) {
				printf(WARNING_IV_NOT_NEEDED);
			}
				
			
			cipher_defined = true;
		}
		//---------------------------
	
	
	
		// Handle invalid argument
		//---------------------------
		else {
			printf(ERROR_INVALID_ARGUMENT, argv[j]);
			exit(1);
		}
		//---------------------------
		
	}
	
	// Post-parsing validity checks
	if (!input_defined) {
		printf(ERROR_NO_INPUT);
		return 1;
	}
	
	if (!output_defined) {
		printf(ERROR_NO_OUTPUT);
		return 1;
	}
	
	if (!cipher_defined) {
		printf(ERROR_NO_CIPHER);
		return 1;
	}
	
	if (!operation_defined) {
		printf(ERROR_NO_OPERATION);
		return 1;
	}
	
	if (key_needed && !key_defined) {
		printf(ERROR_NO_KEY);
		return 1;
	}
	
	if (iv_needed && !iv_defined) {
		printf(ERROR_NO_IV);
		return 1;
	}
	
	// Key checks
	if (use_key_size_bytes && key_len > key_size_bytes) {
		printf(WARNING_KEY_TRUNCATION, key_size_bytes * 8);
		
		key->buffer_len = key_size_bytes;
		key_len = key_size_bytes;
	}
	
	if (use_key_size_bytes && key_len < key_size_bytes) {
		// This should never trigger
		assert(key_size_bytes < BUFFER_SIZE);
		
		printf(WARNING_KEY_ZERO_PADDING, key_size_bytes * 8);
		
		for (unsigned int y = key->buffer_len; y < key_size_bytes; y++) {
			key->buffer[y] = 0;
		}
		
		key->buffer_len = key_size_bytes;
		key_len = key->buffer_len;
	}
	
	// IV generation
	if (will_generate_iv && can_generate_iv && iv_needed && iv_defined) {
		
		srand(time(0));
		byte state[AES_BLOCK_SIZE];
		byte i_key[AES_BLOCK_SIZE];
		
		for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++) {
			state[i] = rand() % 256;
			i_key[i] = rand() % 256;
		}
		
		// Use AES as our CSPRNG
		// Not perfect to create our nonce with rand(), but acceptable enough
		// for this application
		AES_encrypt(state, AES_BLOCK_SIZE, i_key, AES_BLOCK_SIZE);
		iv_len = AES_BLOCK_SIZE;
		
		iv = parse_keywords_to_output_bc(iv_arguments);
		memcpy(iv->buffer, state, AES_BLOCK_SIZE);
		iv->buffer_len = iv_len;
		
		printf("IV generated ");
		iv_buffer = iv->buffer;
		bc_flush(iv);
		printf("\n");
		bc_fclose(iv);
	}
	
	printf("\n");
	
	switch (choosen_cipher) {
		case VIGENERE:
			if (vigenere_keycheck(key_buffer, key_len)) {
				vigenere(input, output, key_buffer, key_len, operation);
				break;
			} else {
				printf("Error: key is invalid for Vigenere cipher.\n");
				break;
			}
		
		case CAESAR: 
			caesar(input, output, operation);
			break;
			
		case SHIFT:
			if (atoi((char*)key_buffer) == 0) {
				printf("Error: key is invalid for shift cipher.\n");
				break;
			}
			
			shift(input, output, atoi((char*)key_buffer), operation);
			break;
			
		case RC4:
			rc4(input, output, key_buffer, key_len, operation);
			break;
		
		case AES:
			switch (choosen_mode) {
				case ECB:
					switch (operation) {
						case ENCRYPT:
							ECB_encrypt(AES_encrypt, input, output, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
					
						case DECRYPT:
							ECB_decrypt(AES_decrypt, input, output, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
							
						default:
							// Future-proofing, should never print
							printf("Error: Unsupported operation for AES: '%d'\n", operation);
							break;
					}
					
					break;
				
				case CBC:
					switch (operation) {
						case ENCRYPT:
							CBC_encrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
					
						case DECRYPT:
							CBC_decrypt(AES_decrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
							
						default:
							// Future-proofing, should never print
							printf("Error: Unsupported operation for AES: '%d'\n", operation);
							break;
					}
					
					break;
					
				case CFB:
					switch (operation) {
						case ENCRYPT:
							CFB_encrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
					
						case DECRYPT:
							CFB_decrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
							
						default:
							// Future-proofing, should never print
							printf("Error: Unsupported operation for AES: '%d'\n", operation);
							break;
					}
					
					break;
					
				case OFB:
					switch (operation) {
						case ENCRYPT:
							OFB_encrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
					
						case DECRYPT:
							OFB_decrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
							
						default:
							// Future-proofing, should never print
							printf("Error: Unsupported operation for AES: '%d'\n", operation);
							break;
					}
					
					break;
				
				case CTR:
					switch (operation) {
						case ENCRYPT:
							CTR_encrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
					
						case DECRYPT:
							CTR_decrypt(AES_encrypt, input, output, iv_buffer, AES_BLOCK_SIZE, AES_BLOCK_SIZE, key_buffer, key_len);
							break;
							
						default:
							// Future-proofing, should never print
							printf("Error: Unsupported operation for AES: '%d'\n", operation);
							break;
					}
					
					break;
			}
	}
	
	printf("\n");
	
	free(input);
	free(output);
	
	if (key != NULL) {
		free(key);
	}
	
	if (iv != NULL) {
		free(iv);
	}
	
	return 0;
}
