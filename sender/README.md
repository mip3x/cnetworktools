# sender
This is packet sender

## Features
- Send packets (only ETH & IP & UDP for now)

## Installation
### Prerequisites
Ensure you have the following dependencies installed:
- GCC (or Clang)
- GNU Make

### Build
To compile the `sender`, run:
```sh
make
```

This will generate an executable named `sender`

## Running the Sender
To start the `sender`, use:
```sh
sudo ./sender
```

## Configuration
Check file `sender.conf`:
- `interface_name`: name of interface from which to send
- `dest_mac_addr`: destination MAC address
