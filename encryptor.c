#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define KEY_LENGTH 32   // AES-256 key length in bytes
#define IV_LENGTH 16    // AES block size for CBC mode

// Global file pointer for logging
FILE *log_file = NULL;

// Function to log errors with a timestamp
void log_error(const char *msg) {
    if (!log_file) {
        log_file = fopen("encryptor.log", "a");
        if (!log_file) {
            fprintf(stderr, "Unable to open log file.\n");
            return;
        }
    }
    time_t now = time(NULL);
    char *timestr = ctime(&now);
    if (timestr) {
        // Remove newline at end of ctime string
        timestr[strlen(timestr) - 1] = '\0';
    }
    fprintf(log_file, "[%s] %s\n", timestr, msg);
    fflush(log_file);
}

// Signal handler to catch fatal signals and log the error
void signal_handler(int signum) {
    char buf[256];
    snprintf(buf, sizeof(buf), "Fatal signal (%d) received. Exiting safely.", signum);
    log_error(buf);
    if (log_file) fclose(log_file);
    exit(EXIT_FAILURE);
}

// AES-256-CBC encryption function using OpenSSL
// plaintext: input data to encrypt
// plaintext_len: length of the plaintext data
// key: 32-byte encryption key
// iv: 16-byte initialization vector
// ciphertext: pointer that will be allocated with the encrypted data (caller must free it)
// Returns the length of the ciphertext on success, or -1 on failure.
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create encryption context.");
        return -1;
    }

    int len = 0, ciphertext_len = 0;
    // Allocate memory for ciphertext (plaintext length + block size)
    *ciphertext = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (*ciphertext == NULL) {
        log_error("Memory allocation failed for ciphertext.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize encryption operation for AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        log_error("Encryption initialization failed.");
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        log_error("Encryption update failed.");
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        log_error("Encryption finalization failed.");
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main(void) {
    // Setup signal handlers for various fatal signals
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Open log file for logging
    log_file = fopen("encryptor.log", "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: encryptor.log\n");
        return EXIT_FAILURE;
    }

    // Create a new ZeroMQ context
    void *context = zmq_ctx_new();
    if (!context) {
        log_error("Failed to create ZeroMQ context.");
        return EXIT_FAILURE;
    }

    // Create a PULL socket for receiving data from the data provider (server role)
    void *receiver = zmq_socket(context, ZMQ_PULL);
    if (!receiver) {
        log_error("Failed to create PULL socket.");
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }
    if (zmq_bind(receiver, "tcp://*:5556") != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Failed to bind PULL socket: %s", zmq_strerror(errno));
        log_error(buf);
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    log_error("Encryptor started successfully.");

    // Define the AES key and IV (for demonstration purposes only)
    const unsigned char key[KEY_LENGTH] = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
    const unsigned char iv[IV_LENGTH]   = "abcdef9876543210";                   // 16 bytes IV

    // Main loop: receive data, encrypt it using AES-256-CBC, and print the ciphertext in hex
    while (1) {
        zmq_msg_t message;
        if (zmq_msg_init(&message) != 0) {
            log_error("Failed to initialize ZeroMQ message.");
            continue;
        }

        int recv_bytes = zmq_msg_recv(&message, receiver, 0);
        if (recv_bytes < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "Failed to receive message: %s", zmq_strerror(errno));
            log_error(buf);
            zmq_msg_close(&message);
            continue;
        }

        // Get the message size and copy the data into a dynamically allocated buffer
        size_t msg_size = zmq_msg_size(&message);
        unsigned char *data = malloc(msg_size);
        if (!data) {
            log_error("Memory allocation failed for incoming message.");
            zmq_msg_close(&message);
            continue;
        }
        memcpy(data, zmq_msg_data(&message), msg_size);
        zmq_msg_close(&message);

        // Encrypt the data using AES-256-CBC
        unsigned char *encrypted_data = NULL;
        int encrypted_size = aes_encrypt(data, msg_size, key, iv, &encrypted_data);
        free(data);  // Free the original data buffer

        if (encrypted_size < 0) {
            log_error("Data encryption failed. Skipping message.");
            continue;
        }

        // Print the encrypted data in hexadecimal format
        printf("Encrypted Data (%d bytes): ", encrypted_size);
        for (int i = 0; i < encrypted_size; i++) {
            printf("%02x", encrypted_data[i]);
        }
        printf("\n");

        free(encrypted_data);
    }

    // Cleanup (this part will not be reached due to the infinite loop)
    zmq_close(receiver);
    zmq_ctx_destroy(context);
    fclose(log_file);

    return EXIT_SUCCESS;
}
