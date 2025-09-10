import type { Vulnerability } from '../types';
import { Severity } from '../types';

interface ApiVuln {
  id: string;
  name: string;
  type: string;
  severity: string;
  cvss: { version: string; score: number };
  epss: number;
  description: string;
  evidence: { file: string; lineNumber: number; codeSnippet: string };
  remediation?: string;
}

export interface ScanResponse {
  target: string;
  count: number;
  findings: ApiVuln[];
}

// Map backend severities to enum
function mapSeverity(s: string): Severity {
  if ((Object.values(Severity) as string[]).includes(s)) return s as Severity;
  return Severity.Medium;
}

export async function runScan(url: string): Promise<Vulnerability[]> {
  const res = await fetch('http://localhost:8000/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, scan: 'all', mode: 'fast', no_ai: true })
  });
  if (!res.ok) throw new Error('Scan failed');
  const data: ScanResponse = await res.json();
  return data.findings.map(v => ({
    id: v.id,
    name: v.name,
    type: v.type as any,
    severity: mapSeverity(v.severity),
    cvss: v.cvss,
    epss: v.epss,
    description: v.description,
    evidence: v.evidence
  }));
}