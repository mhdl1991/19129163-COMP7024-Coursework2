#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <inotify.h>
#include <inotify-syscalls.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <minix/syslib.h>

#define EVENT_SIZE (sizeof (struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))


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

	// initialize ctx
    if(!(ctx = EVP_CIPHER_CTX_new())) { handle_errors(); }

	// initialize encryption
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))  { handle_errors();}

	// encrypt
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length)) { handle_errors(); }
    ciphertext_length = len;

	// finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {handle_errors();}
    ciphertext_length += len;

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
 
static void skeleton_daemon() {
    pid_t pid;
    
    /* Fork off the parent process */
    pid = fork();
    
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);
    
     /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);
    
    /* Catch, ignore and handle signals */
    /* Signal handling goes here */
	
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    /* Fork off for the second time*/
    pid = fork();
    
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);
    
    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    /* Set new file permissions */
    umask(0);
    
    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");
    
    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }
    
    /* Open the log file */
    openlog ("encrypt_daemon", LOG_PID, LOG_DAEMON);
}

int main()
{	
	// load credentials
	unsigned char *key, *iv;
	char *line, buffer[EVENT_BUF_LEN];
	int l_counter = 0, fd, wd, i;
	size_t len = 0;
	ssize_t read;
	// read key and iv from file
	FILE *credentials = fopen("keyfile", "rb");
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

	// daemon setup
    skeleton_daemon();	
	
	fd = inotify_init();	// create inotify instance;
	if ( fd < 0 ) { perror( "inotify_init" ); }
	
	wd = inotify_add_watch( fd,  "/", IN_ALL_EVENTS );

	if(wd<0){
		syslog(LOG_NOTICE, "wd < 0");
		perror("inotify_add_watch");    
	}
	
    while (1)
    {
        //TODO: Insert daemon code here.
        syslog (LOG_NOTICE, "custom file encryption daemon started.");
		/*read to determine the event change happens on directory. Actually this read blocks until the change event occurs*/
		length = read( fd, buffer, EVENT_BUF_LEN );
		
		if (length < 0) {
			perror("read error");
			exit(EXIT_FAILURE);
		}
		char *p = buffer;
		while (p < buffer + length) {
			struct inotify_event* e = (struct inotify_event*)p;
			if (e->mask & IN_CREATE){
				if  (e->mask & IN_ISDIR) {
					syslog(LOG_NOTICE, "new directory %s created\n", e->name);
				} else {
					syslog(LOG_NOTICE, "new file %s created\n", e->name);
				}
			}
			p += EVENT_SIZE + e->length
		}
        sleep (20);
        break;
    }
   
    syslog (LOG_NOTICE, "custom file encryption daemon terminated.");
    closelog();
    
	inotify_rm_watch(fd, wd);
    close(fd);
	
	
    return EXIT_SUCCESS;
}