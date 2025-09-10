export enum Severity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
  Info = 'Info',
}

export type VulnerabilityType = 
  | 'SQLi' 
  | 'XSS' 
  | 'CSRF' 
  | 'SSRF' 
  | 'Security Misconfiguration' 
  | 'Vulnerable Components' 
  | 'Broken Access Control' 
  | 'Cryptographic Failures' 
  | 'Authentication Failures' 
  | 'Integrity Failures' 
  | 'Logging & Monitoring Failure';


export interface Evidence {
  file: string;
  lineNumber: number;
  codeSnippet: string;
}

export interface Vulnerability {
  id: string; 
  name: string;
  type: VulnerabilityType;
  severity: Severity;
  cvss: {
    version: string;
    score: number;
  };
  epss: number;
  description: string;
  evidence: Evidence;
}