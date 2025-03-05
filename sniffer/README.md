# sniffer
This is packet sniffer

## Features
- Sniff packets (only ETH&IP&TCP/UDP for now)

## Installation
### Prerequisites
Ensure you have the following dependencies installed:
- GCC (or Clang)
- GNU Make

### Build
To compile the sniffer, run:
```sh
make
```

This will generate an executable named `sniffer`

## Running the Sniffer
To start the sniffer, use:
```sh
sudo ./server
```

## Configuration
TODO: 
- make interface choosable (loopback etc)
- implement sniffing amount of amap protocols
