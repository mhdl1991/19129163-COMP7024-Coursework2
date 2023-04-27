// test this C program in Lubuntu first?

// file_encrypt() and file_decrypt() adapted from sample encryption and decryption functions provided at 
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

// #include <minix/syslib.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <time.h>

// for debugging only
void print_uchar_buffer(unsigned char *buf, int buf_len) {
	if (!buf) {return;}
	if (!buf_len) {return;}
	for (int i = 0; i < buf_len; i++) { 
	 	printf("%02x ", *(buf + i)); 
		if ((i%8==7) || (i == buf_len - 1) ) {printf("\n");}
	}
}

void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int file_decrypt(char *in_file, char *out_file, unsigned char *key, unsigned char *iv) {
	
	//printf("DECRYPTING FILE:\t%s\n", in_file);
	EVP_CIPHER_CTX *ctx;
	unsigned char *plaintext, *ciphertext;
	int plaintext_length,  ciphertext_length, len;


	FILE *f_in = fopen(in_file, "rb");
	if (f_in) {
		// get the length/size of the ciphertext file
		fseek(f_in, 0, SEEK_END);
		ciphertext_length = ftell(f_in);
		if (!ciphertext_length) {return 1;}
		// return to the start of the ciphertext file
		fseek(f_in, 0, SEEK_SET);
		// declare space for plaintext and ciphertext buffers
		plaintext = malloc(ciphertext_length);
		ciphertext = malloc(ciphertext_length); 
		// read contents of file  into buffer
		if (ciphertext) { fread(ciphertext, 1, ciphertext_length, f_in); }
		fclose(f_in);
	} else {return 1;}
	if (!ciphertext) {return 1;}
	// prints the unsigned char buffer, for debugging purposes
	//printf("Ciphertext buffer:\n");
	//print_uchar_buffer(ciphertext, ciphertext_length);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) { handle_errors(); }
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { handle_errors(); }
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_length)) { handle_errors(); }
    plaintext_length = len;
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) { handle_errors(); }
    plaintext_length += len;

	//printf("Plaintext buffer:\n");
	//print_uchar_buffer(plaintext, plaintext_length);

	/*
	* Write the plaintext buffer to file.
	*/
	FILE *f_out = fopen(out_file, "wb");
	if (f_out) {
		fwrite((unsigned char *) plaintext, plaintext_length, 1, f_out);
		fclose(f_out);		
	}

    /* Clean up */
    if (ctx) { EVP_CIPHER_CTX_free(ctx); }
	if (plaintext) { free(plaintext); }
	if (ciphertext) { free(ciphertext); }
	return 0;
}

int file_encrypt(char *in_file, char *out_file, unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX *ctx;
	unsigned char *plaintext, *ciphertext;
	int plaintext_length,  ciphertext_length, len;
	
	FILE *f_in = fopen(in_file, "rb");
	if (f_in) {									// open the file and read it into  the plaintext_buffer
		fseek(f_in, 0, SEEK_END);			
		plaintext_length = ftell(f_in);			// get the length/size of the plaintext file
		if (!plaintext_length) {return 1;}
		fseek(f_in, 0, SEEK_SET);				// return to the start of the plaintext file
		plaintext = malloc(plaintext_length);	// declare space for plaintext and ciphertext buffers
		ciphertext = malloc(plaintext_length); 
		if (plaintext) { fread(plaintext, 1, plaintext_length, f_in); } 		// read contents of file  into buffer
		fclose(f_in);
	} else { return 1; } 						// failure when opening file
	if (!plaintext) { return 1; }
	
    if(!(ctx = EVP_CIPHER_CTX_new())) { handle_errors(); }     				// Create and initialise the context
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))  { handle_errors();}
    // Provide the message to be encrypted, and obtain the encrypted output.
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length)) { handle_errors(); }
    ciphertext_length = len;
	// Finalise the encryption. Further ciphertext bytes may be written at this stage.
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {handle_errors();}
    ciphertext_length += len;
	// Write the ciphertext buffer to file.
	FILE *f_out = fopen(out_file, "wb");
	if (f_out) {
		fwrite((unsigned char *) ciphertext, ciphertext_length, 1, f_out);
		fclose(f_out);		
	}
    // Cleanup
    if (ctx) { EVP_CIPHER_CTX_free(ctx); }
	// free up buffers
	if (ciphertext) { free(ciphertext); }
	if (plaintext) { free(plaintext); }
	return 0;
}


int main(int argc, char **argv) {

	unsigned char *key, *iv;
	char *line;
	int l_counter = 0;
	size_t len = 0;
	ssize_t read;
	// read key and iv from file
	FILE *credentials = fopen("./keyfile", "rb");
	if (!credentials) {exit(EXIT_FAILURE);}
	while((read = getline(&line, &len, credentials)) != -1) {
		/* A 256 bit key */
		if (l_counter = 0) {key = (unsigned char *) line;}
		/* A 128 bit IV */
		if (l_counter = 1) {iv = (unsigned char *) line;}
		l_counter++;
	}
	if (line) {free(line);}
	fclose(credentials);
	
	/* 
	char *test_in_file = "./in_file.txt", *test_out_file = "./out_file", *test_decrypt_file = "./decrypt_file";
	file_encrypt(test_in_file, test_out_file, key, iv);
	file_decrypt(test_out_file, test_decrypt_file, key, iv);
	*/
	
	char test_file_names_in[10][11] = {"test0.txt","test1.txt","test2.txt","test3.txt","test4.txt","test5.txt","test6.txt","test7.txt","test8.txt","test9.txt"};
	char test_file_names_out[10][11] = {"test0e.txt","test1e.txt","test2e.txt","test3e.txt","test4e.txt","test5e.txt","test6e.txt","test7e.txt","test8e.txt","test9e.txt"};
	
	clock_t start = clock(), diff;
	int msec;
	
	// test encryption time
	printf("Time for encrypting 10 files\n");
	for (int i = 0; i < 10; i++) {
		file_encrypt(test_file_names_in[i], test_file_names_out[i], key, iv);
	}
	diff = clock() - start;
	msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("Time taken %d seconds %d milliseconds\n", msec/1000, msec%1000);

	// test decryption time
	start = clock();
	printf("Time for decrypting 10 files\n");
	for (int i = 0; i < 10; i++) {
		file_decrypt(test_file_names_out[i], test_file_names_in[i], key, iv);
	}
	diff = clock() - start;
	msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("Time taken %d seconds %d milliseconds\n", msec/1000, msec%1000);
	
	return 0;
}
