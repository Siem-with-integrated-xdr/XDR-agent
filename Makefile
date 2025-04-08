.PHONY: all network parent process compressor clean encryptor events health

CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -luser32

# Paths for cJSON
CJSON_INC = -I"lib/cJson"
CJSON_LIB = -L"lib/cJson" -lcjson

# Paths for pcap
PCAP_INC = -I"lib/npcap-sdk-1.15/Include"
PCAP_LIB = -L"lib/npcap-sdk-1.15/Lib/x64" -l wpcap -l Packet -l ws2_32

ZMQ_INC = -I"lib\libzmq\include"
ZMQ_LIB = -L"lib\libzmq\lib" -l:libzmq-v143-mt-gd-4_3_6.lib 

# Paths for COM and WMI
COM_WMI_LIB = -lole32 -luuid -loleaut32 -lpsapi

# Paths for zlib
ZLIB_INC = -I"lib\zstd\lib"
ZLIB_LIB = -L"lib\zstd\lib\dll" -lzstd

# Paths for openssl
OPENSSL_INC = -I"lib\openssl-minimal\include\openssl"
OPENSSL_LIB = -L"lib\openssl-minimal\lib64" -lcrypto

WINEVENT_LIB = -lwevtapi

# Targets
PARENT_TARGET = subprocess_manager.exe
NETWORK_TARGET = network_collector.exe
PROCESS_TARGET = processes_collector.exe
COMPRESSOR_TARGET = compressor.exe
ENCRYPTOR_TARGET = encryptor.exe
EVENTS_TARGET = events_data_collector.exe
HEALTH_TARGET = system_health.exe

PARENT_SRC = parent.c
PARENT_OBJ = $(PARENT_SRC:.c=.o)

NETWORK_SRC = network_data_collector.c
NETWORK_OBJ = $(NETWORK_SRC:.c=.o)

PROCESS_SRC = processes_data_collector.c
PROCESS_OBJ = $(PROCESS_SRC:.c=.o)

COMPRESSOR_SRC = compressor.c
COMPRESSOR_OBJ = $(COMPRESSOR_SRC:.c=.o)

ENCRYPTOR_SRC = encryptor.c
ENCRYPTOR_OBJ = $(ENCRYPTOR_SRC:.c=.o)

EVENTS_SRC = events_data_collector.c
EVENTS_OBJ = $(EVENTS_SRC:.c=.o)

HEALTH_SRC = system_health.c
HEALTH_OBJ = $(HEALTH_SRC:.c=.o)

# Rule for compiling  parent object file
$(PARENT_OBJ): $(PARENT_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for compiling network object file
$(NETWORK_OBJ): $(NETWORK_SRC)
	$(CC) $(CFLAGS) $(CJSON_INC) $(PCAP_INC) $(ZMQ_INC) -c $< -o $@

# Rule for compiling process object file
$(PROCESS_OBJ): $(PROCESS_SRC)
	$(CC) $(CFLAGS) $(CJSON_INC) $(ZMQ_INC) -c $< -o $@

# Rule for compiling compressor object file
$(COMPRESSOR_OBJ): $(COMPRESSOR_SRC)
	$(CC) $(CFLAGS) $(ZMQ_INC) -c $< -o $@

# Rule for compiling encryptor object file
$(ENCRYPTOR_OBJ): $(ENCRYPTOR_SRC)
	$(CC) $(CFLAGS) $(ZMQ_INC) $(OPENSSL_INC) -c $< -o $@

# Rule for compiling events object file
$(EVENTS_OBJ): $(EVENTS_SRC)
	$(CC) $(CFLAGS) $(ZMQ_INC) $(CJSON_INC) -c $< -o $@

# Rule for compiling health object file
$(HEALTH_OBJ): $(HEALTH_SRC)
	$(CC) $(CFLAGS) $(ZMQ_INC) $(CJSON_INC) -c $< -o $@

# Build for subprocess_manager.exe
$(PARENT_TARGET): $(PARENT_OBJ)
	$(CC) $(PARENT_OBJ) -o $(PARENT_TARGET) $(LDFLAGS)

# Build for network_collector.exe
$(NETWORK_TARGET): $(NETWORK_OBJ)
	$(CC) $(NETWORK_OBJ) -o $(NETWORK_TARGET) $(CJSON_LIB) $(PCAP_LIB) $(ZMQ_LIB)

# Build for processes_collector.exe
$(PROCESS_TARGET): $(PROCESS_OBJ)
	$(CC) $(PROCESS_OBJ) -o $(PROCESS_TARGET) $(COM_WMI_LIB) $(CJSON_LIB) $(ZMQ_LIB)

# Build for compressor.exe 
$(COMPRESSOR_TARGET): $(COMPRESSOR_OBJ)
	$(CC) $(COMPRESSOR_OBJ) -o $(COMPRESSOR_TARGET) $(ZMQ_LIB) $(ZLIB_LIB)

# Build for encryptor.exe
$(ENCRYPTOR_TARGET): $(ENCRYPTOR_OBJ)
	$(CC) $(ENCRYPTOR_OBJ) -o $(ENCRYPTOR_TARGET) $(ZMQ_LIB) $(OPENSSL_LIB)

# Build for events_data_collector.exe
$(EVENTS_TARGET): $(EVENTS_OBJ)
	$(CC) $(EVENTS_OBJ) -o $(EVENTS_TARGET) $(ZMQ_LIB) $(CJSON_LIB) $(WINEVENT_LIB)

# Build for system_health.exe
$(HEALTH_TARGET): $(HEALTH_OBJ)
	$(CC) $(HEALTH_OBJ) -o $(HEALTH_TARGET) $(ZMQ_LIB) $(CJSON_LIB) 

# Default target: build everything
all: $(PARENT_TARGET) $(NETWORK_TARGET) $(PARENT_TARGET) $(PROCESS_TARGET) $(COMPRESSOR_TARGET) $(ENCRYPTOR_TARGET) $(EVENTS_TARGET) $(HEALTH_TARGET)

# Build only the network_collector
network: $(NETWORK_TARGET)

# Build only the parent
parent: $(PARENT_TARGET)

# Build only the processes_collector
process: $(PROCESS_TARGET)

# Build only the compressor
compressor: $(COMPRESSOR_TARGET)

# Build only the encryptor
encryptor: $(ENCRYPTOR_TARGET)

# Build only the event
events: $(EVENTS_TARGET)

# Build only the system_health
health: $(HEALTH_TARGET)

clean:
	del $(PARENT_OBJ) $(PARENT_TARGET) $(NETWORK_OBJ) $(NETWORK_TARGET) $(PROCESS_OBJ) $(PROCESS_TARGET) $(COMPRESSOR_OBJ) $(COMPRESSOR_TARGET) $(ENCRYPTOR_OBJ) $(ENCRYPTOR_TARGET) $(EVENTS_OBJ) $(EVENTS_TARGET) $(HELTH_OBJ) $(HELTH_TARGET)
