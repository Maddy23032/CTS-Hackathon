// API service for connecting to VulnScan backend
const isDevelopment = import.meta.env.DEV;
const API_BASE_URL = isDevelopment 
  ? 'http://localhost:8000' 
  : (import.meta.env.VITE_API_URL || 'https://cts-hackathon-oan6.onrender.com');
const WS_BASE_URL = isDevelopment 
  ? 'ws://localhost:8000' 
  : (import.meta.env.VITE_WS_URL || 'wss://cts-hackathon-oan6.onrender.com');
// Groq AI configuration (frontend reference). API key removed — backend proxy handles all enrichment.
export const GROQ_MODEL = 'qwen/qwen3-32b';
// NOTE: No API key here. Backend endpoint /api/ai/enrich performs remediation enrichment securely.

export interface ScanRequest {
  target_url: string;
  scan_types: string[];
  mode: 'fast' | 'full';
  headless: boolean;
  oast: boolean;
  ai_calls: number;
  verbose: boolean;
  max_depth: number;
  delay: number;
}

export interface Vulnerability {
  id: string;
  type: string;
  url: string;
  parameter: string;
  payload: string;
  evidence: string;
  remediation: string;
  cvss: number;
  cvss_version?: string; // Added to align with backend CVSS v4.0 labeling
  epss: number;
  severity: string;
  ai_summary?: string;
  confidence: string;
  timestamp: string;
}

// MongoDB enhanced interfaces
export interface MongoVulnerability {
  _id: string;
  scan_id: string;
  url: string;
  parameter: string;
  payload: string;
  evidence: string;
  type: string;
  severity: string;
  confidence: string;
  remediation?: string;
  cvss_score: number;
  epss_score: number;
  ai_summary?: string;
  created_at: string;
}

export interface Scan {
  scan_id: string;
  target_url: string;
  scan_types: string[];
  mode: string;
  status: string;
  vulnerabilities_found: number;
  created_at: string;
  updated_at: string;
  total_time?: number;
  config?: any;
  stats?: any;
}

export interface ScanHistoryResponse {
  scans: Scan[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface VulnerabilitySearchResponse {
  vulnerabilities: MongoVulnerability[];
  total: number;
  by_type: { [key: string]: number };
  by_severity: { [key: string]: number };
  page: number;
  per_page: number;
}

export interface AnalyticsResponse {
  date_range: string;
  total_scans: number;
  vulnerability_trends: {
    [key: string]: Array<{
      date: string;
      count: number;
    }>;
  };
  scan_success_rate: number;
  daily_data: Array<{
    date: string;
    total_scans: number;
    completed_scans: number;
    failed_scans: number;
    vulnerabilities_found: { [key: string]: number };
    severity_distribution: { [key: string]: number };
    avg_scan_time?: number;
  }>;
}

export interface ScanStatus {
  scan_id: string | null;
  is_scanning: boolean;
  progress: number;
  phase: string;
  current_url?: string;
  current_payload?: string;
  start_time?: string;
  elapsed_time?: number;
  stats: {
    urls_crawled: number;
    forms_found: number;
    requests_sent: number;
    vulnerabilities_found: number;
    ai_calls_made: number;
  };
  config?: any;
  phase_details?: {
    crawl_queue_size?: number;
    scan_queue_size?: number;
    current_depth?: number;
    max_depth?: number;
  };
}

export interface LogEntry {
  timestamp: string;
  message: string;
  level: string;
  scan_id?: string;
  phase?: string;
}

export interface OASTConfig {
  collaborator_url: string;
  auth_token?: string;
  enabled: boolean;
}

export interface OASTStatus {
  status: string;
  collaborator_url: string;
  statistics: {
    total_payloads: number;
    active_payloads: number;
    total_callbacks: number;
    vulnerability_types: Record<string, { payloads: number; callbacks: number }>;
    success_rate: number;
  };
}

export interface OASTPayload {
  id: string;
  payload: string;
  callback_url: string;
  vulnerability_type: string;
  created_at: string;
  expires_at: string;
  scan_id?: string;
  has_callback: boolean;
}

export interface OASTCallback {
  id: string;
  payload_id: string;
  timestamp: string;
  source_ip: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  url: string;
  vulnerability_type: string;
  scan_id?: string;
}

export interface OASTPayloadsResponse {
  status: string;
  payloads: OASTPayload[];
  total: number;
}

export interface OASTCallbacksResponse {
  status: string;
  callbacks: OASTCallback[];
  total: number;
}

class ApiService {
  private websocket: WebSocket | null = null;
  private wsListeners: ((data: any) => void)[] = [];
  // Live cache of vulnerabilities discovered during the current session
  private liveVulnerabilities: Vulnerability[] = [];

  private addLiveVulnerability(v: Vulnerability) {
    this.liveVulnerabilities.push(v);
  }

  private clearLiveVulnerabilities() {
    this.liveVulnerabilities = [];
  }

  getLiveVulnerabilities(): {
    vulnerabilities: Vulnerability[];
    total: number;
    by_type: { [key: string]: number };
  } {
    const by_type: { [key: string]: number } = {};
    for (const v of this.liveVulnerabilities) {
      const t = (v.type || 'unknown').toString().toLowerCase();
      by_type[t] = (by_type[t] || 0) + 1;
    }
    return {
      vulnerabilities: this.liveVulnerabilities,
      total: this.liveVulnerabilities.length,
      by_type,
    };
  }

  // Start a new vulnerability scan
  async startScan(scanRequest: ScanRequest): Promise<{ scan_id: string; status: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/api/scan/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(scanRequest),
    });

    if (!response.ok) {
      throw new Error(`Failed to start scan: ${response.statusText}`);
    }

    return response.json();
  }

  // Get current scan status
  async getScanStatus(): Promise<ScanStatus> {
    const response = await fetch(`${API_BASE_URL}/api/scan/status`);
    
    if (!response.ok) {
      throw new Error(`Failed to get scan status: ${response.statusText}`);
    }

    return response.json();
  }

  // Stop current scan
  async stopScan(): Promise<{ status: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/api/scan/stop`, {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error(`Failed to stop scan: ${response.statusText}`);
    }

    return response.json();
  }

  // Get vulnerabilities found
  async getVulnerabilities(): Promise<{
    vulnerabilities: Vulnerability[];
    total: number;
    by_type: { [key: string]: number };
  }> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/vulnerabilities`);
      if (response.ok) {
        const data = await response.json();
        // If backend returns empty, try fallback
        if (data && Array.isArray(data.vulnerabilities) && data.vulnerabilities.length > 0) {
          return data;
        }
      }
    } catch (e) {
      // ignore and fallback
    }
    // Fallback to live cache
    const fallback = this.getLiveVulnerabilities();
    // Coerce to expected shape
    const ensured = {
      vulnerabilities: fallback.vulnerabilities,
      total: fallback.total,
      by_type: fallback.by_type,
    };
    return ensured;
  }

  // Fallback: if backend is unavailable or returns empty, use live cache
  async getVulnerabilitiesWithFallback(): Promise<{
    vulnerabilities: Vulnerability[];
    total: number;
    by_type: { [key: string]: number };
  }> {
    try {
      const data = await this.getVulnerabilities();
      // If backend has data, prefer it
      if (data && Array.isArray(data.vulnerabilities) && data.vulnerabilities.length > 0) {
        return data as any;
      }
    } catch (e) {
      // Ignore and use fallback
    }
    return this.getLiveVulnerabilities();
  }

  // Get scan logs
  async getScanLogs(): Promise<{ logs: LogEntry[]; total: number }> {
    const response = await fetch(`${API_BASE_URL}/api/scan/logs`);
    
    if (!response.ok) {
      throw new Error(`Failed to get scan logs: ${response.statusText}`);
    }

    return response.json();
  }

  // Trigger AI enrichment
  async triggerAIEnrichment(): Promise<{ status: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/api/ai/enrich`, {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error(`Failed to trigger AI enrichment: ${response.statusText}`);
    }

    return response.json();
  }

  // Legacy method name for backward compatibility
  async enrichVulnerabilities(): Promise<{ status: string; message: string }> {
    return this.triggerAIEnrichment();
  }

  // ==================== NEW MONGODB ENDPOINTS ====================

  /**
   * Get scan history with filtering and pagination
   */
  async getScanHistory(params: {
    page?: number;
    per_page?: number;
    status?: string;
    target_url?: string;
    scan_type?: string;
    date_from?: string;
    date_to?: string;
  } = {}): Promise<ScanHistoryResponse> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        searchParams.append(key, value.toString());
      }
    });

    const response = await fetch(`${API_BASE_URL}/api/scan/history?${searchParams}`);
    
    if (!response.ok) {
      throw new Error(`Failed to get scan history: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get detailed information about a specific scan
   */
  async getScanDetails(scanId: string): Promise<{
    scan: Scan;
    vulnerabilities: VulnerabilitySearchResponse;
    logs: Array<{
      timestamp: string;
      level: string;
      message: string;
    }>;
  }> {
    const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}`);
    
    if (!response.ok) {
      throw new Error(`Failed to get scan details: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Search and filter vulnerabilities
   */
  async searchVulnerabilities(params: {
    scan_id?: string;
    vuln_type?: string;
    severity?: string;
    page?: number;
    per_page?: number;
  } = {}): Promise<VulnerabilitySearchResponse> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        searchParams.append(key, value.toString());
      }
    });

    const response = await fetch(`${API_BASE_URL}/api/vulnerabilities/search?${searchParams}`);
    
    if (!response.ok) {
      throw new Error(`Failed to search vulnerabilities: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get analytics data
   */
  async getAnalytics(days: number = 30): Promise<AnalyticsResponse> {
    const response = await fetch(`${API_BASE_URL}/api/analytics?days=${days}`);
    
    if (!response.ok) {
      throw new Error(`Failed to get analytics: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Manually update analytics
   */
  async updateAnalytics(date?: string): Promise<{ status: string; message: string }> {
    const body = date ? JSON.stringify({ date }) : undefined;
    
    const response = await fetch(`${API_BASE_URL}/api/analytics/update`, {
      method: 'POST',
      headers: body ? {
        'Content-Type': 'application/json',
      } : {},
      body,
    });

    if (!response.ok) {
      throw new Error(`Failed to update analytics: ${response.statusText}`);
    }

    return response.json();
  }

  /** Rebuild analytics for past N days (server recomputes historical documents). */
  async rebuildAnalytics(days: number = 90): Promise<{ status: string; rebuilt_days: number }> {
    const response = await fetch(`${API_BASE_URL}/api/analytics/rebuild?days=${days}`, {
      method: 'POST'
    });
    if (!response.ok) {
      throw new Error(`Failed to rebuild analytics: ${response.statusText}`);
    }
    return response.json();
  }

  /** Refresh analytics for a specific scan id (updates that scan's day). */
  async refreshAnalyticsForScan(scanId: string): Promise<{ status: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/api/analytics/refresh_for_scan/${scanId}`, {
      method: 'POST'
    });
    if (!response.ok) {
      throw new Error(`Failed to refresh analytics for scan: ${response.statusText}`);
    }
    return response.json();
  }

  /**
   * Download scan report (if implemented)
   */
  async downloadReport(scanId: string, format: 'json' | 'csv' | 'pdf' | 'html' = 'html'): Promise<Blob> {
    const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/report?format=${format}&include_ai_analysis=true`);
    
    if (!response.ok) {
      throw new Error(`Failed to download report: ${response.statusText}`);
    }

    return response.blob();
  }

  /**
   * Export vulnerabilities data
   */
  async exportVulnerabilities(params: {
    scan_id?: string;
    format?: 'json' | 'csv';
    vuln_type?: string;
    severity?: string;
  } = {}): Promise<Blob> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        searchParams.append(key, value.toString());
      }
    });

    const response = await fetch(`${API_BASE_URL}/api/vulnerabilities/export?${searchParams}`);
    
    if (!response.ok) {
      throw new Error(`Failed to export vulnerabilities: ${response.statusText}`);
    }

    return response.blob();
  }

  // WebSocket connection for real-time updates
  connectWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.websocket = new WebSocket(`${WS_BASE_URL}/ws/scan-updates`);

        this.websocket.onopen = () => {
          console.log('WebSocket connected');
          resolve();
        };

        this.websocket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            // Update local vulnerability cache on relevant events
            if (data?.type === 'scan_started') {
              this.clearLiveVulnerabilities();
            }
      if (data?.type === 'vulnerability_found' && data.vulnerability) {
              const v = data.vulnerability as any;
              const mapped: Vulnerability = {
        id: v.id || (typeof crypto !== 'undefined' && 'randomUUID' in crypto ? (crypto as any).randomUUID() : Math.random().toString(36).slice(2)),
                type: v.type || 'unknown',
                url: v.url || '',
                parameter: v.parameter || '',
                payload: v.payload || '',
                evidence: v.evidence || '',
                remediation: v.remediation || '',
                cvss: typeof v.cvss === 'number' ? v.cvss : 0,
                epss: typeof v.epss === 'number' ? v.epss : 0,
                severity: v.severity || 'Medium',
                ai_summary: v.ai_summary,
                confidence: v.confidence || 'Medium',
                timestamp: new Date().toISOString(),
              };
              this.addLiveVulnerability(mapped);
            }
            // Notify all listeners
            this.wsListeners.forEach(listener => listener(data));
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.websocket.onclose = () => {
          console.log('WebSocket disconnected');
          // Attempt to reconnect after 3 seconds
          setTimeout(() => {
            if (this.wsListeners.length > 0) {
              this.connectWebSocket();
            }
          }, 3000);
        };

        this.websocket.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(error);
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  // Add listener for WebSocket messages
  addWebSocketListener(listener: (data: any) => void): void {
    this.wsListeners.push(listener);
  }

  // Remove WebSocket listener
  removeWebSocketListener(listener: (data: any) => void): void {
    const index = this.wsListeners.indexOf(listener);
    if (index > -1) {
      this.wsListeners.splice(index, 1);
    }
  }

  // Disconnect WebSocket
  disconnectWebSocket(): void {
    if (this.websocket) {
      this.websocket.close();
      this.websocket = null;
    }
    this.wsListeners = [];
  }

  // Check if backend is available
  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE_URL}/`);
      return response.ok;
    } catch (error) {
      console.error('Backend health check failed:', error);
      return false;
    }
  }

  // ==================== OAST METHODS ====================

  async configureOAST(config: OASTConfig): Promise<any> {
    const response = await fetch(`${API_BASE_URL}/api/oast/configure`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(config),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async getOASTStatus(): Promise<OASTStatus> {
    const response = await fetch(`${API_BASE_URL}/api/oast/status`);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async getOASTPayloads(scanId?: string, vulnerabilityType?: string): Promise<OASTPayloadsResponse> {
    const params = new URLSearchParams();
    if (scanId) params.append('scan_id', scanId);
    if (vulnerabilityType) params.append('vulnerability_type', vulnerabilityType);

    const response = await fetch(`${API_BASE_URL}/api/oast/payloads?${params}`);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async getOASTCallbacks(payloadId?: string, scanId?: string): Promise<OASTCallbacksResponse> {
    const params = new URLSearchParams();
    if (payloadId) params.append('payload_id', payloadId);
    if (scanId) params.append('scan_id', scanId);

    const response = await fetch(`${API_BASE_URL}/api/oast/callbacks?${params}`);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async generateOASTPayloads(vulnerabilityType: string, scanId?: string): Promise<any> {
    const response = await fetch(`${API_BASE_URL}/api/oast/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        vulnerability_type: vulnerabilityType,
        scan_id: scanId,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async cleanupOAST(): Promise<any> {
    const response = await fetch(`${API_BASE_URL}/api/oast/cleanup`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }
}

// Export singleton instance
export const apiService = new ApiService();
export default apiService;
