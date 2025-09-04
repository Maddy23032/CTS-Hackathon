// API service for connecting to VulnPy backend
const API_BASE_URL = 'http://localhost:8000';
const WS_BASE_URL = 'ws://localhost:8000';

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
    top_targets: Array<{ url: string; count: number }>;
    avg_scan_time?: number;
  }>;
}

export interface ScanStatus {
  scan_id: string | null;
  is_scanning: boolean;
  progress: number;
  phase: string;
  stats: {
    urls_crawled: number;
    forms_found: number;
    requests_sent: number;
    vulnerabilities_found: number;
    ai_calls_made: number;
  };
  config?: any;
}

export interface LogEntry {
  timestamp: string;
  message: string;
  level: string;
  scan_id?: string;
  phase?: string;
}

class ApiService {
  private websocket: WebSocket | null = null;
  private wsListeners: ((data: any) => void)[] = [];

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
    by_type: {
      xss: number;
      sqli: number;
      csrf: number;
    };
  }> {
    const response = await fetch(`${API_BASE_URL}/api/vulnerabilities`);
    
    if (!response.ok) {
      throw new Error(`Failed to get vulnerabilities: ${response.statusText}`);
    }

    return response.json();
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

  /**
   * Download scan report (if implemented)
   */
  async downloadReport(scanId: string, format: 'json' | 'csv' | 'pdf' = 'json'): Promise<Blob> {
    const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/report?format=${format}`);
    
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
}

// Export singleton instance
export const apiService = new ApiService();
export default apiService;
