CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -luser32

# Paths for cJSON
CJSON_INC = -I"lib/cJson"
CJSON_LIB = -L"lib/cJson" -lcjson

# Paths for Network Data Collector
PCAP_INC = -I"lib/npcap-sdk-1.15/Include"
PCAP_LIB = -L"lib/npcap-sdk-1.15/Lib/x64" -l wpcap -l Packet -l ws2_32

# Targets
TARGET = subprocess_manager.exe
NETWORK_TARGET = network_collector.exe

SRC = main.c
OBJ = $(SRC:.c=.o)

NETWORK_SRC = network_data_collector.c
NETWORK_OBJ = $(NETWORK_SRC:.c=.o)

# Default target: build everything
all: $(TARGET) $(NETWORK_TARGET)

# Build for subprocess_manager.exe
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

# Build for network_collector.exe with cJSON
$(NETWORK_TARGET): $(NETWORK_OBJ)
	$(CC) $(NETWORK_OBJ) -o $(NETWORK_TARGET) $(CJSON_LIB) $(PCAP_LIB)

# Rule for compiling object files
%.o: %.c
	$(CC) $(CFLAGS) $(CJSON_INC) $(PCAP_INC) -c $< -o $@

# Build only the network_collector
network: $(NETWORK_TARGET)

clean:
	del $(OBJ) $(TARGET) $(NETWORK_OBJ) $(NETWORK_TARGET)
