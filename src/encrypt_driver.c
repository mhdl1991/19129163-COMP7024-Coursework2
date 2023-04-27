#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// minix encryption / decryption driver


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
	
	//printf("ENCRYPTING FILE:\t%s\n", in_file);
	EVP_CIPHER_CTX *ctx;
	unsigned char *plaintext, *ciphertext;
	int plaintext_length,  ciphertext_length, len;
	

	FILE *f_in = fopen(in_file, "rb");
	// open the file and read it into  the plaintext_buffer
	if (f_in) {
		// get the length/size of the plaintext file
		fseek(f_in, 0, SEEK_END);
		plaintext_length = ftell(f_in);
		if (!plaintext_length) {return 1;}
		// return to the start of the plaintext file
		fseek(f_in, 0, SEEK_SET);

		// declare space for plaintext and ciphertext buffers
		plaintext = malloc(plaintext_length);
		ciphertext = malloc(plaintext_length); 

		// read contents of file  into buffer
		if (plaintext) { fread(plaintext, 1, plaintext_length, f_in); }
		fclose(f_in);
	} else { return 1; } // failure when opening file
	if (!plaintext) { return 1; }
	// prints the unsigned char buffer, for debugging purposes
	//printf("Plaintext buffer:\n");
	//print_uchar_buffer(plaintext, plaintext_length);

	// encrypt the buffer using AES
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) { handle_errors(); }
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))  { handle_errors();}
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length)) { handle_errors(); }
    ciphertext_length = len;
	/*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {handle_errors();}
    ciphertext_length += len;

	//printf("Ciphertext buffer:\n");
	//print_uchar_buffer(ciphertext, ciphertext_length);

	/*
	* Write the ciphertext buffer to file.
	*/
	FILE *f_out = fopen(out_file, "wb");
	if (f_out) {
		fwrite((unsigned char *) ciphertext, ciphertext_length, 1, f_out);
		fclose(f_out);		
	}

    /* Clean up */
    if (ctx) { EVP_CIPHER_CTX_free(ctx); }
	// free up buffers
	if (ciphertext) { free(ciphertext); }
	if (plaintext) { free(plaintext); }
	return 0;
}


 

 
static void sef_local_startup() {
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);
 
    /*
     * Register live update callbacks.
     */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);
 
    /* Let SEF perform startup. */
    sef_startup();
}
 
 
int main(void)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();
 
    /*
     * Run the main loop.
     */
    //chardriver_task(&hello_tab);
    return OK;
}