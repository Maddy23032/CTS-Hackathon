import { useState, useEffect, useCallback } from 'react';
import { apiService, ScanRequest, ScanStatus, Vulnerability, LogEntry } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

// Hook for managing scan operations
export const useScan = () => {
  const [scanStatus, setScanStatus] = useState<ScanStatus>({
    scan_id: null,
    is_scanning: false,
    progress: 0,
    phase: 'idle',
    stats: {
      urls_crawled: 0,
      forms_found: 0,
      requests_sent: 0,
      vulnerabilities_found: 0,
      ai_calls_made: 0,
    },
  });
  const [isConnected, setIsConnected] = useState(false);
  const { toast } = useToast();

  // Start a new scan
  const startScan = useCallback(async (scanRequest: ScanRequest) => {
    try {
      const result = await apiService.startScan(scanRequest);
      toast({
        title: "Scan Started",
        description: result.message,
      });
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start scan';
      toast({
        title: "Error",
        description: message,
        variant: "destructive",
      });
      throw error;
    }
  }, [toast]);

  // Stop current scan
  const stopScan = useCallback(async () => {
    try {
      const result = await apiService.stopScan();
      toast({
        title: "Scan Stopped",
        description: result.message,
      });
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to stop scan';
      toast({
        title: "Error",
        description: message,
        variant: "destructive",
      });
      throw error;
    }
  }, [toast]);

  // Refresh scan status
  const refreshStatus = useCallback(async () => {
    try {
      const status = await apiService.getScanStatus();
      setScanStatus(status);
    } catch (error) {
      console.error('Failed to refresh scan status:', error);
    }
  }, []);

  // Check backend connection
  const checkConnection = useCallback(async () => {
    const connected = await apiService.healthCheck();
    setIsConnected(connected);
    return connected;
  }, []);

  // Setup WebSocket and polling
  useEffect(() => {
    // Check initial connection
    checkConnection();

    // Setup WebSocket for real-time updates
    const connectWS = async () => {
      try {
        await apiService.connectWebSocket();
        setIsConnected(true);
      } catch (error) {
        console.error('Failed to connect WebSocket:', error);
        setIsConnected(false);
      }
    };

    connectWS();

    // WebSocket message handler
    const handleWebSocketMessage = (data: any) => {
      switch (data.type) {
        case 'scan_started':
          refreshStatus();
          break;
        case 'phase_update':
          setScanStatus(prev => ({
            ...prev,
            phase: data.phase,
            progress: data.progress,
          }));
          break;
        case 'crawling_complete':
          setScanStatus(prev => ({
            ...prev,
            progress: data.progress,
            stats: {
              ...prev.stats,
              urls_crawled: data.urls_found,
              forms_found: data.forms_found,
            },
          }));
          break;
        case 'vulnerabilities_found':
          setScanStatus(prev => ({
            ...prev,
            stats: {
              ...prev.stats,
              vulnerabilities_found: prev.stats.vulnerabilities_found + data.count,
            },
          }));
          break;
        case 'scan_complete':
          setScanStatus(prev => ({
            ...prev,
            is_scanning: false,
            progress: 100,
            phase: 'complete',
            stats: {
              ...prev.stats,
              vulnerabilities_found: data.total_vulnerabilities,
            },
          }));
          toast({
            title: "Scan Complete",
            description: `Found ${data.total_vulnerabilities} vulnerabilities`,
          });
          break;
        case 'scan_stopped':
          setScanStatus(prev => ({
            ...prev,
            is_scanning: false,
            phase: 'stopped',
          }));
          break;
        case 'scan_error':
          setScanStatus(prev => ({
            ...prev,
            is_scanning: false,
            phase: 'error',
          }));
          toast({
            title: "Scan Error",
            description: data.error,
            variant: "destructive",
          });
          break;
      }
    };

    apiService.addWebSocketListener(handleWebSocketMessage);

    // Cleanup
    return () => {
      apiService.removeWebSocketListener(handleWebSocketMessage);
    };
  }, [toast, refreshStatus, checkConnection]);

  // Poll status when not connected via WebSocket
  useEffect(() => {
    if (!isConnected) {
      const interval = setInterval(refreshStatus, 2000);
      return () => clearInterval(interval);
    }
  }, [isConnected, refreshStatus]);

  return {
    scanStatus,
    isConnected,
    startScan,
    stopScan,
    refreshStatus,
    checkConnection,
  };
};

// Hook for managing vulnerabilities
export const useVulnerabilities = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [vulnStats, setVulnStats] = useState({
    total: 0,
    by_type: { xss: 0, sqli: 0, csrf: 0 },
  });
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  // Fetch vulnerabilities
  const fetchVulnerabilities = useCallback(async () => {
    setIsLoading(true);
    try {
      const result = await apiService.getVulnerabilities();
      setVulnerabilities(result.vulnerabilities);
      setVulnStats({
        total: result.total,
        by_type: result.by_type,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch vulnerabilities';
      toast({
        title: "Error",
        description: message,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  }, [toast]);

  // Trigger AI enrichment
  const enrichVulnerabilities = useCallback(async () => {
    try {
      const result = await apiService.enrichVulnerabilities();
      toast({
        title: "AI Enrichment",
        description: result.message,
      });
      // Refresh vulnerabilities to get updated AI summaries
      await fetchVulnerabilities();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to enrich vulnerabilities';
      toast({
        title: "Error",
        description: message,
        variant: "destructive",
      });
    }
  }, [toast, fetchVulnerabilities]);

  // Auto-refresh vulnerabilities when new ones are found
  useEffect(() => {
    const handleWebSocketMessage = (data: any) => {
      if (data.type === 'vulnerabilities_found' || data.type === 'ai_enrichment_complete') {
        fetchVulnerabilities();
      }
    };

    apiService.addWebSocketListener(handleWebSocketMessage);

    return () => {
      apiService.removeWebSocketListener(handleWebSocketMessage);
    };
  }, [fetchVulnerabilities]);

  return {
    vulnerabilities,
    vulnStats,
    isLoading,
    fetchVulnerabilities,
    enrichVulnerabilities,
  };
};

// Hook for managing scan logs
export const useScanLogs = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Fetch scan logs
  const fetchLogs = useCallback(async () => {
    setIsLoading(true);
    try {
      const result = await apiService.getScanLogs();
      setLogs(result.logs);
    } catch (error) {
      console.error('Failed to fetch scan logs:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Auto-update logs via WebSocket
  useEffect(() => {
    const handleWebSocketMessage = (data: any) => {
      if (data.type === 'log_update') {
        setLogs(prev => [...prev, data.entry]);
      }
    };

    apiService.addWebSocketListener(handleWebSocketMessage);

    return () => {
      apiService.removeWebSocketListener(handleWebSocketMessage);
    };
  }, []);

  return {
    logs,
    isLoading,
    fetchLogs,
  };
};
