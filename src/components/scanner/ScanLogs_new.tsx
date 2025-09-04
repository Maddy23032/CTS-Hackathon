import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Terminal, Activity, Pause, Play, RotateCcw, Trash2, Download } from 'lucide-react';
import { apiService, LogEntry } from '@/lib/api';

interface ScanLogsProps {
  isScanning: boolean;
  scanId?: string | null;
}

export function ScanLogs({ isScanning, scanId }: ScanLogsProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const [isWebSocketConnected, setIsWebSocketConnected] = useState(false);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const fallbackIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // WebSocket message handler
  const handleWebSocketMessage = useCallback((data: any) => {
    if (isPaused) return; // Don't update if paused

    if (data.type === 'log_update' && data.entry) {
      const logEntry: LogEntry = {
        level: data.entry.level || 'info',
        message: data.entry.message || '',
        timestamp: data.entry.timestamp || new Date().toISOString(),
        scan_id: data.entry.scan_id,
        phase: data.entry.phase
      };

      setLogs(prevLogs => {
        // Avoid duplicate logs
        const isDuplicate = prevLogs.some(log => 
          log.message === logEntry.message && 
          Math.abs(new Date(log.timestamp).getTime() - new Date(logEntry.timestamp).getTime()) < 1000
        );
        
        if (!isDuplicate) {
          const newLogs = [...prevLogs, logEntry];
          // Keep only last 500 logs to prevent memory issues
          return newLogs.slice(-500);
        }
        return prevLogs;
      });
    }
  }, [isPaused]);

  // Fallback polling for when WebSocket is not available
  const setupFallbackPolling = useCallback(() => {
    if (fallbackIntervalRef.current) {
      clearInterval(fallbackIntervalRef.current);
    }

    if (isScanning && !isPaused && !isWebSocketConnected) {
      fallbackIntervalRef.current = setInterval(async () => {
        try {
          const response = await apiService.getScanLogs();
          setLogs(response.logs || []);
        } catch (error) {
          console.error('Fallback polling failed:', error);
        }
      }, 3000); // Poll every 3 seconds as fallback
    }
  }, [isScanning, isPaused, isWebSocketConnected]);

  // Initial load of existing logs
  const fetchLogs = async () => {
    try {
      setLoading(true);
      const response = await apiService.getScanLogs();
      setLogs(response.logs || []);
    } catch (error) {
      console.error('Failed to fetch scan logs:', error);
    } finally {
      setLoading(false);
    }
  };

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (isAutoScroll && scrollAreaRef.current) {
      const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]');
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight;
      }
    }
  }, [logs, isAutoScroll]);

  // WebSocket connection management
  useEffect(() => {
    const connectWebSocket = async () => {
      try {
        await apiService.connectWebSocket();
        setIsWebSocketConnected(true);
        apiService.addWebSocketListener(handleWebSocketMessage);
        console.log('WebSocket connected for ScanLogs');
      } catch (error) {
        console.error('Failed to connect WebSocket:', error);
        setIsWebSocketConnected(false);
      }
    };

    connectWebSocket();

    // Cleanup on unmount
    return () => {
      apiService.removeWebSocketListener(handleWebSocketMessage);
      if (fallbackIntervalRef.current) {
        clearInterval(fallbackIntervalRef.current);
      }
    };
  }, [handleWebSocketMessage]);

  // Setup fallback polling when WebSocket is not available
  useEffect(() => {
    setupFallbackPolling();
    return () => {
      if (fallbackIntervalRef.current) {
        clearInterval(fallbackIntervalRef.current);
      }
    };
  }, [setupFallbackPolling]);

  // Initial load
  useEffect(() => {
    fetchLogs();
  }, []);

  // Handle scanning state changes
  useEffect(() => {
    if (isScanning && !isPaused) {
      // Optionally fetch initial logs when scanning starts
      fetchLogs();
    }
  }, [isScanning, isPaused]);

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error': return 'text-severity-critical';
      case 'warning': return 'text-status-warning';
      case 'success': return 'text-status-success';
      case 'info':
      default: return 'text-foreground';
    }
  };

  const getLevelBadge = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error': return 'bg-severity-critical text-destructive-foreground';
      case 'warning': return 'bg-status-warning text-foreground';
      case 'success': return 'bg-status-success text-foreground';
      case 'info':
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const pauseResumeLogs = () => {
    setIsPaused(!isPaused);
    if (isPaused) {
      // When resuming, fetch latest logs
      fetchLogs();
    }
  };

  const downloadLogs = () => {
    const logText = logs.map(log => 
      `[${formatTimestamp(log.timestamp)}] ${log.level.toUpperCase()}: ${log.message}`
    ).join('\n');
    
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vuln-scan-logs-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch {
      return timestamp;
    }
  };

  const getConnectionStatus = () => {
    if (isWebSocketConnected) {
      return isScanning ? 'Live' : 'Connected';
    }
    return 'Polling';
  };

  const getConnectionBadgeStyle = () => {
    if (isWebSocketConnected) {
      return isScanning 
        ? 'bg-status-scanning text-foreground animate-pulse-glow'
        : 'bg-status-success text-foreground';
    }
    return 'bg-status-warning text-foreground';
  };

  return (
    <Card className="bg-gradient-security border-border">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg text-foreground flex items-center gap-2">
            <Terminal className="h-5 w-5 text-primary" />
            Scan Logs
            <Badge className={getConnectionBadgeStyle()}>
              <Activity className="h-3 w-3 mr-1" />
              {getConnectionStatus()}
            </Badge>
            {isPaused && (
              <Badge variant="outline" className="bg-yellow-500/20 text-yellow-700">
                Paused
              </Badge>
            )}
          </CardTitle>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={pauseResumeLogs}
              className={isPaused ? 'bg-green-500/20 text-green-700' : 'bg-yellow-500/20 text-yellow-700'}
              title={isPaused ? 'Resume log updates' : 'Pause log updates'}
            >
              {isPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
              {isPaused ? 'Resume' : 'Pause'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsAutoScroll(!isAutoScroll)}
              className={isAutoScroll ? 'bg-primary/20' : ''}
              title={isAutoScroll ? 'Disable auto-scroll' : 'Enable auto-scroll'}
            >
              {isAutoScroll ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              Scroll
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={downloadLogs}
              disabled={logs.length === 0}
              title="Download logs as text file"
            >
              <Download className="h-4 w-4" />
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={clearLogs}
              className="text-destructive hover:bg-destructive/20"
              title="Clear all logs"
            >
              <Trash2 className="h-4 w-4" />
              Clear
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {/* Connection Status Info */}
          {!isWebSocketConnected && (
            <div className="bg-yellow-500/20 border border-yellow-500/50 rounded-lg p-2 text-sm text-yellow-700 dark:text-yellow-300">
              ⚠️ WebSocket unavailable. Using fallback polling every 3 seconds.
            </div>
          )}
          
          {/* Logs Display */}
          <ScrollArea 
            ref={scrollAreaRef}
            className="h-64 w-full border border-border rounded-lg bg-card p-4"
          >
            {loading && logs.length === 0 ? (
              <div className="text-center py-8">
                <Terminal className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground">Loading logs...</p>
              </div>
            ) : logs.length === 0 ? (
              <div className="text-center py-8">
                <Terminal className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground">No logs available</p>
                <p className="text-xs text-muted-foreground mt-1">Start a scan to see real-time logs</p>
              </div>
            ) : (
              <div className="space-y-2 font-mono text-sm">
                {logs.map((log, index) => (
                  <div key={`${log.timestamp}-${index}`} className="flex items-start gap-3 p-2 rounded hover:bg-secondary/20">
                    <div className="flex items-center gap-2 min-w-0 flex-shrink-0">
                      <Badge className={`${getLevelBadge(log.level)} text-xs`}>
                        {log.level.toUpperCase()}
                      </Badge>
                      <span className="text-xs text-muted-foreground font-mono">
                        {formatTimestamp(log.timestamp)}
                      </span>
                      {(log as any).phase && (
                        <Badge variant="outline" className="text-xs">
                          {(log as any).phase}
                        </Badge>
                      )}
                    </div>
                    <div className={`flex-1 min-w-0 ${getLevelColor(log.level)}`}>
                      <p className="break-words whitespace-pre-wrap">{log.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>

          {/* Log Statistics */}
          <div className="flex justify-between items-center text-xs text-muted-foreground bg-secondary/20 rounded p-2">
            <span>Total Logs: {logs.length}</span>
            <span>
              Mode: {isPaused ? 'Paused' : isWebSocketConnected ? 'Real-time' : 'Polling (3s)'}
            </span>
            {isScanning && (
              <span className="text-status-scanning animate-pulse">● Scanning...</span>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
