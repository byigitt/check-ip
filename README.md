# IP VPN Checker

A Go service that checks if an IP address belongs to a VPN, proxy, or Tor exit node.

## Features

- Fast IP checking with bloom filters
- Automatic updates of VPN/proxy IP lists
- RESTful API with Gin
- Concurrent processing of multiple IP sources
- Supports both individual IPs and CIDR ranges

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/byigitt/check-ip.git
   cd check-ip
   ```

2. Install dependencies:

   ```
   go mod tidy
   ```

3. Build the executable:
   ```
   go build -o ip-checker ./cmd
   ```

## Usage

### Running the Server

```
./ip-checker
```

The server will start on port 8080 by default. The first run will download and process all VPN IP lists, which may take a few minutes.

### API Endpoints

- `GET /api/check/:ip` - Check if an IP is a VPN/proxy
- `POST /api/check` - Check if an IP is a VPN/proxy (JSON body with "ip" field)
- `GET /api/stats` - Get bloom filter statistics
- `GET /health` - Health check

### Example Requests

Check an IP (GET):

```
curl http://localhost:8080/api/check/1.2.3.4
```

Check an IP (POST):

```
curl -X POST -H "Content-Type: application/json" -d '{"ip":"1.2.3.4"}' http://localhost:8080/api/check
```

## Data Sources

The service fetches IP data from multiple sources:

- X4BNet VPN lists
- TOR exit nodes
- Various proxy lists
- And more

## Configuration

The default configuration can be overridden by modifying the values in the config package or by implementing environment variable support.

## License

MIT
