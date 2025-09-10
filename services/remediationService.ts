import type { Vulnerability } from '../types';

const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || (window as any).API_BASE_URL || 'http://localhost:8000';

export async function fetchRemediation(v: Vulnerability): Promise<string> {
  const res = await fetch(`${API_BASE}/api/remediation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      vulnerability_type: v.type,
      url: v.evidence.file,
      parameter: '',
      evidence: v.evidence.codeSnippet,
      payload: ''
    })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Remediation request failed (${res.status}): ${text}`);
  }
  const data = await res.json();
  return data.remediation || 'No remediation available';
}