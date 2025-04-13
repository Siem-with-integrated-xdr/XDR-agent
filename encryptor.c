#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <rdkafka.h>   // Kafka producer
#include <libxml/parser.h>
#include <libxml/tree.h>

#define KEY_LENGTH 32   // AES-256 key length in bytes
#define IV_LENGTH 16    // AES block size for CBC mode

// Global file pointer for logging
FILE *log_file = NULL;

// ---------------------------------------------------------------------------
// Logging function: Logs errors with a timestamp to encryptor.log
// ---------------------------------------------------------------------------
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
        // Remove newline at the end of ctime output
        timestr[strlen(timestr) - 1] = '\0';
    }
    fprintf(log_file, "[%s] %s\n", timestr, msg);
    fflush(log_file);
}

// ---------------------------------------------------------------------------
// Signal handler to catch fatal signals and log the error before exit
// ---------------------------------------------------------------------------
void signal_handler(int signum) {
    char buf[256];
    snprintf(buf, sizeof(buf), "Fatal signal (%d) received. Exiting safely.", signum);
    log_error(buf);
    if (log_file) fclose(log_file);
    exit(EXIT_FAILURE);
}

// ---------------------------------------------------------------------------
// AES-256-CBC encryption function using OpenSSL
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Structure to hold configuration details from the XML file
// ---------------------------------------------------------------------------
typedef struct {
    char kafka_broker_ip[64];
    int kafka_broker_port;
    char kafka_topic[64];  // New field for Kafka topic
} Config;

// ---------------------------------------------------------------------------
// Function to load and parse the XML configuration file using libxml2.
// Extracts the Kafka broker IP, port, and topic.
// ---------------------------------------------------------------------------
int load_config(const char *filename, Config *config) {
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
    
    // Parse the XML file
    doc = xmlReadFile(filename, NULL, 0);
    if (doc == NULL) {
        fprintf(stderr, "Could not parse the XML configuration file: %s\n", filename);
        return -1;
    }
    
    // Get the root element node
    root_element = xmlDocGetRootElement(doc);
    if (root_element == NULL) {
        fprintf(stderr, "The configuration file %s is empty.\n", filename);
        xmlFreeDoc(doc);
        return -1;
    }
    
    // Traverse the XML tree to locate the <kafka> element
    xmlNode *cur_node = NULL;
    for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE && strcmp((const char *)cur_node->name, "kafka") == 0) {
            xmlNode *node = NULL;
            for (node = cur_node->children; node; node = node->next) {
                if (node->type == XML_ELEMENT_NODE) {
                    if (strcmp((const char *)node->name, "broker_ip") == 0) {
                        xmlChar *ip = xmlNodeGetContent(node);
                        if (ip) {
                            strncpy(config->kafka_broker_ip, (const char *)ip, sizeof(config->kafka_broker_ip) - 1);
                            config->kafka_broker_ip[sizeof(config->kafka_broker_ip) - 1] = '\0';
                            xmlFree(ip);
                        }
                    } else if (strcmp((const char *)node->name, "broker_port") == 0) {
                        xmlChar *port_str = xmlNodeGetContent(node);
                        if (port_str) {
                            config->kafka_broker_port = atoi((const char *)port_str);
                            xmlFree(port_str);
                        }
                    } else if (strcmp((const char *)node->name, "topic") == 0) {
                        xmlChar *topic = xmlNodeGetContent(node);
                        if (topic) {
                            strncpy(config->kafka_topic, (const char *)topic, sizeof(config->kafka_topic) - 1);
                            config->kafka_topic[sizeof(config->kafka_topic) - 1] = '\0';
                            xmlFree(topic);
                        }
                    }
                }
            }
        }
    }
    
    // Clean up
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}

// ---------------------------------------------------------------------------
// Main function: Sets up signal handlers, loads configuration from XML,
// initializes ZeroMQ and Kafka, encrypts incoming messages, and sends them
// to Kafka.
// ---------------------------------------------------------------------------
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

    // Load XML configuration for Kafka
    Config config;
    if (load_config("config.xml", &config) != 0){
        fprintf(stderr, "Error loading configuration file. Using defaults.\n");
        log_error("Error loading configuration file. Using defaults.");
        strcpy(config.kafka_broker_ip, "localhost");
        config.kafka_broker_port = 9092;
        strcpy(config.kafka_topic, "encrypted_topic");
    }
    
    // Build the bootstrap servers string (e.g., "localhost:9092")
    char bootstrap_servers[128];
    snprintf(bootstrap_servers, sizeof(bootstrap_servers), "%s:%d", 
             config.kafka_broker_ip, config.kafka_broker_port);

    // Create a new ZeroMQ context
    void *context = zmq_ctx_new();
    if (!context) {
        log_error("Failed to create ZeroMQ context.");
        return EXIT_FAILURE;
    }

    // Create a PULL socket for receiving data from the provider
    void *receiver = zmq_socket(context, ZMQ_PULL);
    if (!receiver) {
        log_error("Failed to create PULL socket.");
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }
    // Bind to port 5556 (adjust if needed)
    if (zmq_bind(receiver, "tcp://*:5556") != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Failed to bind PULL socket: %s", zmq_strerror(errno));
        log_error(buf);
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    // ----------------- Kafka Producer Setup -----------------
    char errstr[512];
    rd_kafka_conf_t *kafka_conf = rd_kafka_conf_new();

    // Set the bootstrap servers using the XML configuration
    if (rd_kafka_conf_set(kafka_conf, "bootstrap.servers", bootstrap_servers,
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        log_error("Kafka config bootstrap.servers error.");
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        fclose(log_file);
        return EXIT_FAILURE;
    }

    // Create the Kafka producer instance
    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_conf, errstr, sizeof(errstr));
    if (!rk) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Failed to create Kafka producer: %.200s", errstr);
        log_error(buf);
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        fclose(log_file);
        return EXIT_FAILURE;
    }

    // Create a Kafka topic object using the topic from XML configuration
    rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, config.kafka_topic, NULL);
    if (!rkt) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Failed to create Kafka topic object: %s",
                 rd_kafka_err2str(rd_kafka_last_error()));
        log_error(buf);
        rd_kafka_destroy(rk);
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        fclose(log_file);
        return EXIT_FAILURE;
    }
    // ---------------------------------------------------------

    log_error("Encryptor started successfully.");

    // Define the AES key and IV (for demonstration purposes only)
    const unsigned char key[KEY_LENGTH] = "0123456789abcdef0123456789abcdef"; // 32-byte key for AES-256
    const unsigned char iv[IV_LENGTH]   = "abcdef9876543210";                   // 16-byte IV

    // Main loop: receive data, encrypt it using AES-256-CBC, and send it to Kafka
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

        // Copy the received data into a dynamically allocated buffer
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

        // Send the encrypted data to Kafka using the RD_KAFKA_MSG_F_COPY flag
        if (rd_kafka_produce(
                rkt,                        // Kafka topic object
                RD_KAFKA_PARTITION_UA,      // Use automatic partitioning
                RD_KAFKA_MSG_F_COPY,        // Copy the payload
                (void *)encrypted_data,     // Message payload
                encrypted_size,             // Message size in bytes
                NULL, 0,                    // Optional key (none used)
                NULL                        // Message opaque (none used)
            ) == -1) {
            char kafka_err[256];
            snprintf(kafka_err, sizeof(kafka_err),
                     "Failed to produce Kafka message: %s",
                     rd_kafka_err2str(rd_kafka_last_error()));
            log_error(kafka_err);
        }

        // Free the encrypted data buffer (we used the copy flag)
        free(encrypted_data);

        // Poll Kafka to handle delivery reports and internal events (non-blocking)
        rd_kafka_poll(rk, 0);
    }

    // Cleanup (this section is reached when you exit the loop)
    rd_kafka_flush(rk, 10000);  // Wait up to 10 seconds for message delivery
    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
    zmq_close(receiver);
    zmq_ctx_destroy(context);
    fclose(log_file);

    return EXIT_SUCCESS;
}
