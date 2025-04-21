import { FastMCP, type ServerOptions } from "fastmcp";
import dotenv from 'dotenv';
import { ipFilterTool } from './ipFilterTool';

dotenv.config();

// Create a new FastMCP server instance with typed configuration
const serverConfig: ServerOptions<undefined> = {
    name: "IP Filter Server",
    version: "0.0.1",
};

export const server = new FastMCP(serverConfig);

// Add tools to server
server.addTool(ipFilterTool);

// Start the server
const port = process.env.PORT ? parseInt(process.env.PORT) : 3000;

console.log('Starting MCP server on port', port);
server.start({
    transportType: 'sse',
    sse: {
        endpoint: '/sse',
        port,
    },
}); 