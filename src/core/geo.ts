/** A hand-rolled stand-in for MaxMind. Real GeoIP databases are tens of MB and
 *  need a licence key; this covers the ranges the bundled samples use plus the
 *  RFC5737 documentation nets, which is all the impossible-travel rule needs.
 *  Anything unknown just returns undefined and the rule stays quiet. */

export interface GeoLoc {
  city: string;
  country: string;
  cc: string;
  lat: number;
  lon: number;
  org: string;
}

interface Row extends GeoLoc {
  cidr: string;
}

export const GEO_TABLE: Row[] = [
  // RFC1918 / internal
  { cidr: '10.0.0.0/8', city: 'Frankfurt DC', country: 'Germany', cc: 'DE', lat: 50.11, lon: 8.68, org: 'Internal (corp)' },
  { cidr: '172.16.0.0/12', city: 'Frankfurt DC', country: 'Germany', cc: 'DE', lat: 50.11, lon: 8.68, org: 'Internal (corp)' },
  { cidr: '192.168.0.0/16', city: 'Office LAN', country: 'Germany', cc: 'DE', lat: 50.11, lon: 8.68, org: 'Internal (corp)' },

  // documentation ranges - stand in for "the internet" in the samples
  { cidr: '203.0.113.0/24', city: 'Bucharest', country: 'Romania', cc: 'RO', lat: 44.43, lon: 26.11, org: 'AS9009 M247' },
  { cidr: '198.51.100.0/24', city: 'Sao Paulo', country: 'Brazil', cc: 'BR', lat: -23.55, lon: -46.63, org: 'AS263073 Hostwind' },
  { cidr: '192.0.2.0/24', city: 'Ashburn', country: 'United States', cc: 'US', lat: 39.04, lon: -77.49, org: 'AS14061 DigitalOcean' },

  // routable ranges used by the impossible-travel and scanner scenarios
  { cidr: '82.102.20.0/22', city: 'London', country: 'United Kingdom', cc: 'GB', lat: 51.51, lon: -0.13, org: 'AS9009 M247' },
  { cidr: '103.21.244.0/22', city: 'Singapore', country: 'Singapore', cc: 'SG', lat: 1.35, lon: 103.82, org: 'AS13335 Cloudflare' },
  { cidr: '185.220.101.0/24', city: 'Nuremberg', country: 'Germany', cc: 'DE', lat: 49.45, lon: 11.08, org: 'AS205100 F3 Netze (Tor exit)' },
  { cidr: '45.83.220.0/22', city: 'Amsterdam', country: 'Netherlands', cc: 'NL', lat: 52.37, lon: 4.9, org: 'AS60117 Host Sailor' },
  { cidr: '91.219.236.0/22', city: 'Moscow', country: 'Russia', cc: 'RU', lat: 55.75, lon: 37.62, org: 'AS49505 Selectel' },
  { cidr: '41.220.108.0/22', city: 'Lagos', country: 'Nigeria', cc: 'NG', lat: 6.52, lon: 3.38, org: 'AS37282 MainOne' },
  { cidr: '159.223.0.0/16', city: 'Bangalore', country: 'India', cc: 'IN', lat: 12.97, lon: 77.59, org: 'AS14061 DigitalOcean' },
  { cidr: '77.83.36.0/22', city: 'Sofia', country: 'Bulgaria', cc: 'BG', lat: 42.7, lon: 23.32, org: 'AS204957 Neterra' },
];

function ipToLong(ip: string): number | null {
  const p = ip.split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    const b = Number(part);
    if (!Number.isInteger(b) || b < 0 || b > 255) return null;
    n = n * 256 + b;
  }
  return n;
}

interface Compiled {
  base: number;
  mask: number;
  bits: number;
  loc: GeoLoc;
}

const COMPILED: Compiled[] = GEO_TABLE.map((r) => {
  const [addr, bitsStr] = r.cidr.split('/');
  const bits = Number(bitsStr);
  const base = ipToLong(addr)!;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const { cidr: _cidr, ...loc } = r;
  return { base: (base & mask) >>> 0, mask, bits, loc };
  // longest prefix wins, so sort below
}).sort((a, b) => b.bits - a.bits);

export function geoLookup(ip: string | undefined): GeoLoc | undefined {
  if (!ip) return undefined;
  const n = ipToLong(ip);
  if (n === null) return undefined;
  const hit = COMPILED.find((c) => ((n & c.mask) >>> 0) === c.base);
  return hit?.loc;
}

export function isPrivate(ip: string | undefined): boolean {
  if (!ip) return false;
  return /^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

/** Great-circle distance in km. */
export function haversineKm(a: GeoLoc, b: GeoLoc): number {
  const R = 6371;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lon - a.lon) * Math.PI) / 180;
  const la1 = (a.lat * Math.PI) / 180;
  const la2 = (b.lat * Math.PI) / 180;
  const h =
    Math.sin(dLat / 2) ** 2 + Math.sin(dLon / 2) ** 2 * Math.cos(la1) * Math.cos(la2);
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

export type GeoResolver = (ip: string | undefined) => GeoLoc | undefined;
