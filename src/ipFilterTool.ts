import { type Tool } from "fastmcp";
import * as ipaddr from "ipaddr.js";
import { z } from "zod";
import fetch from "node-fetch";

// Schema 
const ipFilterParameters = z.object({
    ip_address: z.string().describe("IPv4 or IPv6 address to check"),
    cidr_ranges: z.array(z.string()).describe("Array of CIDR ranges to check against"),
    check_tor: z.boolean().default(false).describe("Check if the IP address is a Tor exit node"),
});

type IpFilterArgs = z.infer<typeof ipFilterParameters>;

// Cache for Tor exit nodes
let torExitNodes: string[] = [];
let lastTorFetch: number = 0;
const TOR_CACHE_TTL = 60 * 60 * 1000; // 1 hour in milliseconds

/**
 * Fetch list of Tor exit nodes
 */
async function fetchTorExitNodes(): Promise<string[]> {
    // If cache is still valid, return cached data
    const now = Date.now();
    if (torExitNodes.length > 0 && (now - lastTorFetch) < TOR_CACHE_TTL) {
        return torExitNodes;
    }

    try {
        // Fetch the Tor exit node list from the official Tor Project
        const response = await fetch('https://check.torproject.org/exit-addresses');
        const text = await response.text();

        // Parse the response to extract IP addresses
        const exitNodes = text
            .split('\n')
            .filter((line: string) => line.startsWith('ExitAddress'))
            .map((line: string) => line.split(' ')[1]);

        // Update cache
        torExitNodes = exitNodes;
        lastTorFetch = now;

        return exitNodes;
    } catch (error) {
        console.error('Error fetching Tor exit nodes:', error);
        // If fetch fails but we have a cached list, return the cached list
        if (torExitNodes.length > 0) {
            return torExitNodes;
        }
        return [];
    }
}

/**
 * Check if an IP address is a Tor exit node
 */
async function isTorExitNode(ipAddress: string): Promise<boolean> {
    const exitNodes = await fetchTorExitNodes();
    return exitNodes.includes(ipAddress);
}

/**
 * Checks if an IP address is contained within any of the given CIDR ranges
 */
function isInCIDRRange(ipAddress: string, cidrRanges: string[]): { result: boolean; error?: string } {
    try {
        // Parse the IP address
        const addr = ipaddr.parse(ipAddress);

        // Process each CIDR range
        for (const cidr of cidrRanges) {
            try {
                // Skip empty CIDR ranges
                if (!cidr || cidr.trim() === '') {
                    continue;
                }

                // Handle inputs without a slash by adding /32 for IPv4 or /128 for IPv6
                let processedCidr = cidr;
                if (!cidr.includes('/')) {
                    try {
                        const rangeAddr = ipaddr.parse(cidr);
                        if (rangeAddr.kind() === 'ipv4') {
                            processedCidr = `${cidr}/32`;
                        } else {
                            processedCidr = `${cidr}/128`;
                        }
                    } catch (e) {
                        continue; // Skip invalid CIDRs instead of failing the whole operation
                    }
                }

                // Validate CIDR format
                try {
                    const [rangeParsedIP, rangeNetmask] = ipaddr.parseCIDR(processedCidr);

                    // Handle IPv4 addresses
                    if (addr.kind() === 'ipv4' && rangeParsedIP.kind() === 'ipv4') {
                        const ipv4 = addr as ipaddr.IPv4;
                        const rangeIpv4 = rangeParsedIP as ipaddr.IPv4;
                        if (ipv4.match([rangeIpv4, rangeNetmask])) {
                            return { result: true };
                        }
                    }

                    // Handle IPv6 addresses
                    if (addr.kind() === 'ipv6' && rangeParsedIP.kind() === 'ipv6') {
                        const ipv6 = addr as ipaddr.IPv6;
                        const rangeIpv6 = rangeParsedIP as ipaddr.IPv6;
                        if (ipv6.match([rangeIpv6, rangeNetmask])) {
                            return { result: true };
                        }
                    }

                    // Handle IPv4-mapped IPv6 addresses
                    else if (addr.kind() === 'ipv6' && rangeParsedIP.kind() === 'ipv4') {
                        const ipv6 = addr as ipaddr.IPv6;
                        if (ipv6.isIPv4MappedAddress()) {
                            const ipv4 = ipv6.toIPv4Address();
                            const rangeIpv4 = rangeParsedIP as ipaddr.IPv4;
                            if (ipv4.match([rangeIpv4, rangeNetmask])) {
                                return { result: true };
                            }
                        }
                    }
                } catch (e) {
                    // Continue to the next CIDR range instead of failing
                    continue;
                }
            } catch (e) {
                // Continue to the next CIDR range
                continue;
            }
        }

        return { result: false };
    } catch (e) {
        return { result: false, error: `Invalid IP address: ${ipAddress}` };
    }
}

export const ipFilterTool: Tool<undefined> = {
    name: "filter_ip",
    description: "Validates if an IPv4 or IPv6 address is within allowed ranges or is a Tor exit node",
    parameters: ipFilterParameters,
    execute: async (args: any) => {
        const { ip_address, cidr_ranges, check_tor } = args as IpFilterArgs;

        // Validate IP address format first
        try {
            ipaddr.parse(ip_address);
        } catch (e) {
            return {
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        result: false,
                        error: `Invalid IP address format: ${ip_address}`
                    })
                }]
            };
        }

        // Validate CIDR ranges
        if (!cidr_ranges || cidr_ranges.length === 0) {
            return {
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        result: false,
                        error: "No CIDR ranges provided"
                    })
                }]
            };
        }

        // Validate each CIDR format
        const invalidCidrs: string[] = [];
        for (const cidr of cidr_ranges) {
            if (!cidr || cidr.trim() === '') {
                invalidCidrs.push(cidr);
                continue;
            }

            try {
                // First test if the IP part is valid
                let ipPart = cidr;
                if (cidr.includes('/')) {
                    ipPart = cidr.split('/')[0];
                }
                ipaddr.parse(ipPart);

                // If it has a slash, test the complete CIDR
                if (cidr.includes('/')) {
                    ipaddr.parseCIDR(cidr);
                }
            } catch (e) {
                invalidCidrs.push(cidr);
            }
        }

        if (invalidCidrs.length > 0) {
            return {
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        result: false,
                        error: `Invalid CIDR ranges: ${invalidCidrs.join(', ')}`
                    })
                }]
            };
        }

        // Check CIDR ranges
        const cidrCheckResult = isInCIDRRange(ip_address, cidr_ranges);
        if (!cidrCheckResult.result || cidrCheckResult.error) {
            return {
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        result: false,
                        error: cidrCheckResult.error || "IP address is not in any of the valid CIDR ranges"
                    })
                }]
            };
        }

        // If already within CIDR ranges and not checking for Tor, return early
        if (cidrCheckResult.result && !check_tor) {
            return {
                content: [{
                    type: "text",
                    text: JSON.stringify({ result: true })
                }]
            };
        }

        // Check if IP is a Tor exit node if requested
        if (check_tor) {
            const isTorExit = await isTorExitNode(ip_address);
            if (isTorExit) {
                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify({
                            result: false,
                            error: `IP address ${ip_address} is a Tor exit node`
                        })
                    }]
                };
            }
        }

        // Final result based on CIDR check
        return {
            content: [{
                type: "text",
                text: JSON.stringify({ result: cidrCheckResult.result })
            }]
        };
    },
}; 