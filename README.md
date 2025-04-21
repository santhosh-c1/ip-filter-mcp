# IP Filter MCP Server

A Model Context Protocol (MCP) server with tools for IP validation and filtering using FastMCP.

## Features

- IP address validation tool supporting both IPv4 and IPv6
- Configurable CIDR range checking for IP filtering
- Tor exit node detection capability
- Simple interface via MCP for use with AI assistants

## Setup

1. Install dependencies:
```bash
yarn install
```

2. Start the server:
```bash
# Start with stdio transport (default)
yarn start

# Test with FastMCP CLI tool
yarn dev

# Inspect with FastMCP Inspector
yarn inspect
```

## Available Tools

### IP Filter Tool
The main tool provided by this server is the IP filtering functionality:

- **Validates** both IPv4 and IPv6 addresses
- **Checks** if an IP is within specified CIDR ranges
- **Detects** if an IP is a Tor exit node (optional)
- **Handles** IPv4-mapped IPv6 addresses for compatibility

#### Parameters:
- `ip_address`: IPv4 or IPv6 address to check (string)
- `cidr_ranges`: Array of CIDR ranges to validate against (string[])
- `check_tor`: Whether to check if the IP is a Tor exit node (boolean, default: false)

#### Example Usage:
```json
{
  "ip_address": "192.168.1.1",
  "cidr_ranges": ["192.168.0.0/16", "10.0.0.0/8"],
  "check_tor": true
}
```

## Using with Claude or other AI assistants

To use this server with Claude Desktop or other AI assistants that support MCP, follow the [MCP Quickstart Guide](https://modelcontextprotocol.io/quickstart/user) and add the following configuration:

```json
{
  "mcpServers": {
    "ip-filter-mcp": {
      "command": "yarn",
      "args": [
        "tsx",
        "/path/to/your/ip-filter-mcp/src/index.ts"
      ],
      "env": {
        "TRANSPORT_TYPE": "stdio"
      }
    }
  }
}
```

Replace `/path/to/your/ip-filter-mcp` with the actual path to your project directory.

## Built With

- [FastMCP](https://github.com/punkpeye/fastmcp) - A TypeScript framework for building MCP servers
- [Zod](https://github.com/colinhacks/zod) - TypeScript-first schema validation library
- [ipaddr.js](https://github.com/whitequark/ipaddr.js) - IP address manipulation library