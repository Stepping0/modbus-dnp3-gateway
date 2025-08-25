# Modbus → DNP3 Gateway

This project is a gateway application that converts Modbus/TCP traffic to DNP3 protocol.

## Features

- **Modbus/TCP PCAP Parser**: Analyzes Modbus traffic from PCAP files and outputs in JSON format
- **Protocol Gateway**: Converts JSON data to DNP3 protocol  
- **DNP3 Outstation**: DNP3 outstation simulation using OpenDNP3 library
- **DNP3 Master**: Test DNP3 master application

## Requirements

### System Requirements
- CMake (3.10+) 
- GCC/G++ compiler
- Linux/Unix-based operating system

### Libraries
- `libpcap-dev` - For packet capture
- OpenDNP3 - DNP3 protocol implementation
- `nlohmann/json` - JSON processing (single-header)

### Installation (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install cmake build-essential libpcap-dev
```

## Build

```bash
# In project directory
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

## Usage

### 1. Extract JSON from PCAP File

```bash
# Process demo PCAP file
./build/modbus_pcap2json captures/demo.pcapng

# Output file: json_kayit/modbus_output.json
```

### 2. Point Mapping Configuration

Map Modbus addresses to DNP3 point types in `mapping/point_map.conf`:

```
# Format: ModbusAddr = DNP3Type, DNP3Index
40001 = Analog, 0
40002 = Analog, 1  
40003 = Analog, 2
10001 = Binary, 0
10002 = Binary, 1
```

**Supported DNP3 Types:**
- `Analog` - Analog Input (30001-39999 → DNP3 AI)
- `Binary` - Binary Input (10001-19999 → DNP3 BI)

### 3. Start DNP3 Outstation

```bash
./build/dnp3_outstation
```

**Configuration:**
- Listen Address: `0.0.0.0:20000`
- Local Address: 10
- Remote Address: 1

### 4. Test with DNP3 Master

```bash
# New terminal window
./build/dnp3_master
```

**Configuration:**
- Connection: `127.0.0.1:20000`
- Local Address: 1  
- Remote Address: 10

## Project Structure

```
├── src/                    # Source code
│   ├── modbus_pcap2json.c     # PCAP parser
│   ├── dnp3_outstation.cpp    # DNP3 outstation
│   └── dnp3_master.cpp        # DNP3 master test
├── include/                # Header files
├── mapping/                # Configuration files
│   └── point_map.conf         # Point mapping
├── captures/               # Sample PCAP files
├── json_kayit/            # Parser outputs
├── build/                 # Compiled files
└── CMakeLists.txt         # CMake configuration
```

## Data Flow

1. **Modbus PCAP** → `modbus_pcap2json` → **JSON file**
2. **JSON + Mapping** → `dnp3_outstation` → **DNP3 Outstation**  
3. **DNP3 Master** → Read data from outstation

## Security Warnings

⚠️ **Warning**: This tool is for testing and development purposes only.

- Perform comprehensive security testing before production use
- Use in isolated test networks
- Configure firewall rules appropriately

## Notes

- Default outstation link addresses: Local=10, Remote=1 (Master should use reverse)
- Use only in isolated test environments before production
