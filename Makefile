CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -luser32

# Paths for cJSON
CJSON_INC = -I"lib/cJson"
CJSON_LIB = -L"lib/cJson" -lcjson

# Paths for Network Data Collector
PCAP_INC = -I"lib/npcap-sdk-1.15/Include"
PCAP_LIB = -L"lib/npcap-sdk-1.15/Lib/x64" -l wpcap -l Packet -l ws2_32

# Paths for COM and WMI
COM_WMI_LIB = -lole32 -luuid -loleaut32 -lpsapi

# Targets
PARENT_TARGET = subprocess_manager.exe
NETWORK_TARGET = network_collector.exe
PROCESS_TARGET = processes_collector.exe

PARENT_SRC = main.c
PARENT_OBJ = $(PARENT_SRC:.c=.o)

NETWORK_SRC = network_data_collector.c
NETWORK_OBJ = $(NETWORK_SRC:.c=.o)

PROCESS_SRC = processes_data_collector.c
PROCESS_OBJ = $(PROCESS_SRC:.c=.o)

# Rule for compiling object files
$(PARENT_OBJ): $(PARENT_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for compiling object files
$(NETWORK_OBJ): $(NETWORK_SRC)
	$(CC) $(CFLAGS) $(CJSON_INC) $(PCAP_INC) -c $< -o $@

# Rule for compiling object files
$(PROCESS_OBJ): $(PROCESS_SRC)
	$(CC) $(CFLAGS) $(CJSON_INC) -c $< -o $@

# Build for subprocess_manager.exe
$(PARENT_TARGET): $(PARENT_OBJ)
	$(CC) $(PARENT_OBJ) -o $(PARENT_TARGET) $(LDFLAGS)

# Build for network_collector.exe with cJSON
$(NETWORK_TARGET): $(NETWORK_OBJ)
	$(CC) $(NETWORK_OBJ) -o $(NETWORK_TARGET) $(CJSON_LIB) $(PCAP_LIB)

# Build for network_collector.exe with cJSON
$(PROCESS_TARGET): $(PROCESS_OBJ)
	$(CC) $(PROCESS_OBJ) -o $(PROCESS_TARGET) $(COM_WMI_LIB) $(CJSON_LIB)

# Default target: build everything
all: $(PARENT_TARGET) $(NETWORK_TARGET)

# Build only the network_collector
network: $(NETWORK_TARGET)

# Build only the network_collector
parent: $(PARENT_TARGET)

# Build only the network_collector
process: $(PROCESS_TARGET)

clean:
	del $(PARENT_OBJ) $(PARENT_TARGET) $(NETWORK_OBJ) $(NETWORK_TARGET) $(PROCESS_OBJ) $(PROCESS_TARGET)
