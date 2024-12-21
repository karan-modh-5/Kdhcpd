# Kdhcpd - A Simple DHCP Server

`kdhcpd` is a lightweight DHCP server implemented in Python. It allows you to temporarily allocate IP addresses to devices in a local network with features like Grandstream-specific filtering and configurable network parameters.

## Features

- Dynamically allocate IP addresses within a specified range.
- Configurable subnet mask, gateway IP, and DNS server IP.
- Grandstream device filtering based on MAC address prefixes.
- Verbose mode for detailed logging.
- Compatible with IPv4 networks.
- Easy-to-use command-line interface for configuration.

## Requirements

- Python 3.7 or later
- `ipaddress` module (built-in with Python 3.3+)

## Installation

1. Clone this repository or download the `kdhcpd.py` file.
2. Ensure Python 3.7+ is installed on your system.

## Usage

Run the script from the command line with appropriate arguments:

```bash
python kdhcpd.py [OPTIONS]
```

### Available Options

| Option          | Description                                                  | Example                        |
|------------------|--------------------------------------------------------------|--------------------------------|
| `-DS`           | Starting DHCP IP Address                                     | `-DS 192.168.1.10`            |
| `-DE`           | Ending DHCP IP Address                                       | `-DE 192.168.1.50`            |
| `-n`            | Subnet Mask                                                  | `-n 255.255.255.0`            |
| `-g`            | Gateway IP Address                                           | `-g 192.168.1.1`              |
| `-d`            | DNS IP Address                                               | `-d 8.8.8.8`                  |
| `-G`            | Provide IPs only to Grandstream devices                      | `-G`                          |
| `-V` / `--verbose` | Enable verbose mode for detailed logging                   | `-V`                          |
| `-v`            | Print version info                                           | `-v`                          |

### Example

Start a DHCP server for the `192.168.1.0/24` network:

```bash
python kdhcpd.py -DS 192.168.1.10 -DE 192.168.1.50 -n 255.255.255.0 -g 192.168.1.1 -d 8.8.8.8 -G -V
```

This configuration:
- Allocates IPs between `192.168.1.10` and `192.168.1.50`.
- Uses `255.255.255.0` as the subnet mask.
- Sets `192.168.1.1` as the gateway.
- Sets `8.8.8.8` as the DNS server.
- Filters requests to serve only Grandstream devices.
- Enables verbose logging for debugging.

## Features for Grandstream Devices

The script supports filtering requests to allocate IPs only to Grandstream devices. It uses Organizationally Unique Identifiers (OUIs) to identify devices. Supported OUIs include:

- `00:0B:82`
- `00:0B:46`
- `AC:CF:23`
- `C0:74:AD`
- `EC:74:D7`

## Troubleshooting

- **Server not stopping with `Ctrl+C`**: Ensure the script is running in a terminal that supports signal interruption. If the issue persists, restart the terminal.
- **No IP allocated**: Verify that the specified IP range is within the subnet and the device matches the OUI filter.
- **Verbose output missing**: Use the `-V` flag to enable verbose logging.
