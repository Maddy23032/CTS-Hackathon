import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { 
  Play, 
  Pause, 
  Square, 
  Clock, 
  Globe, 
  Target, 
  Bug, 
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Zap,
  Database,
  Brain
} from 'lucide-react';
import { useScan } from '@/hooks/useScan';
import { ScanRequest, apiService, Vulnerability } from '@/lib/api';

interface ScanMonitorProps {
  isOpen: boolean;
  onClose: () => void;
  scanRequest: ScanRequest;
}

interface ScanLog {
  id: string;
  timestamp: Date;
  level: 'info' | 'warning' | 'error' | 'success';
  phase: string;
  message: string;
  details?: any;
}

export function ScanMonitor({ isOpen, onClose, scanRequest }: ScanMonitorProps) {
  const { scanStatus, stopScan, isConnected } = useScan();
  const [startTime, setStartTime] = useState<Date | null>(null);
  const [elapsedTime, setElapsedTime] = useState('00:00:00');
  const [scanLogs, setScanLogs] = useState<ScanLog[]>([]);
  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [currentPayload, setCurrentPayload] = useState<string>('');
  const [urlsFound, setUrlsFound] = useState<string[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [historyDurationSec, setHistoryDurationSec] = useState<number | null>(null);

  // --- Persistence helpers (localStorage) ---
  const getStoreKey = (scanId?: string | null) =>
    scanId ? `scan.monitor.state.${scanId}` : 'scan.monitor.state.current';

  const saveState = (scanId?: string | null) => {
    try {
      const key = getStoreKey(scanId ?? scanStatus.scan_id);
      const payload = {
        scan_id: scanId ?? scanStatus.scan_id,
        target_url: scanRequest?.target_url,
        start_time: startTime ? startTime.toISOString() : undefined,
        logs: scanLogs.slice(0, 500).map(l => ({
          id: l.id,
          timestamp: l.timestamp instanceof Date ? l.timestamp.toISOString() : l.timestamp,
          level: l.level,
          phase: l.phase,
          message: l.message,
          details: l.details,
        })),
        urls: urlsFound.slice(-500),
        current_url: currentUrl,
        current_payload: currentPayload,
        vulns: vulns.slice(0, 500),
        last_saved: new Date().toISOString(),
      };
      localStorage.setItem(key, JSON.stringify(payload));
    } catch {}
  };

  const tryRestoreState = () => {
    try {
      const keyPreferred = getStoreKey(scanStatus.scan_id);
      const keyFallback = getStoreKey();
      const raw = localStorage.getItem(keyPreferred) || localStorage.getItem(keyFallback);
      if (!raw) return false;
      const parsed = JSON.parse(raw);
      if (parsed.start_time && !startTime) {
        const dt = new Date(parsed.start_time);
        if (!isNaN(dt.getTime())) setStartTime(dt);
      }
      if (Array.isArray(parsed.logs) && parsed.logs.length > 0 && scanLogs.length === 0) {
        const restoredLogs: ScanLog[] = parsed.logs.map((l: any) => ({
          id: l.id || Math.random().toString(36).substr(2, 9),
          timestamp: new Date(l.timestamp),
          level: l.level,
          phase: l.phase,
          message: l.message,
          details: l.details,
        }));
        setScanLogs(restoredLogs);
      }
      if (Array.isArray(parsed.urls) && parsed.urls.length > 0 && urlsFound.length === 0) {
        setUrlsFound(parsed.urls);
      }
      if (parsed.current_url && !currentUrl) setCurrentUrl(parsed.current_url);
      if (parsed.current_payload && !currentPayload) setCurrentPayload(parsed.current_payload);
      if (Array.isArray(parsed.vulns) && parsed.vulns.length > 0 && vulns.length === 0) {
        setVulns(parsed.vulns);
      }
      return true;
    } catch {
      return false;
    }
  };

  // Load data for "View Last Scan" (when not actively scanning)
  useEffect(() => {
    const loadScanHistory = async () => {
      if (!scanStatus.is_scanning && isOpen) {
        try {
          // Get the most recent scan from history
          const scanHistoryResponse = await apiService.getScanHistory({ page: 1, per_page: 1 });
          if (scanHistoryResponse.scans.length > 0) {
            const lastScan = scanHistoryResponse.scans[0];
            // Load detailed logs and vulnerabilities for the last scan
            try {
              const details = await apiService.getScanDetails(lastScan.scan_id);
              if (details?.logs) {
                const formatted: ScanLog[] = details.logs.map((l: any) => ({
                  id: Math.random().toString(36).substr(2, 9),
                  timestamp: new Date(l.timestamp),
                  level: (l.level || 'info') as ScanLog['level'],
                  phase: (l.phase || 'general') as string,
                  message: l.message,
                }));
                setScanLogs(formatted);
              }
              if (details?.vulnerabilities?.vulnerabilities) {
                const mapped = (details.vulnerabilities.vulnerabilities as any[]).map(v => ({
                  id: v._id || v.id || Math.random().toString(36).substr(2, 9),
                  type: v.type,
                  url: v.url,
                  parameter: v.parameter,
                  payload: v.payload,
                  evidence: v.evidence || '',
                  remediation: v.remediation || '',
                  cvss: typeof v.cvss_score === 'number' ? v.cvss_score : (v.cvss || 0),
                  epss: typeof v.epss_score === 'number' ? v.epss_score : (v.epss || 0),
                  severity: v.severity || 'Medium',
                  ai_summary: v.ai_summary,
                  confidence: v.confidence || 'Medium',
                  timestamp: v.created_at || new Date().toISOString(),
                })) as Vulnerability[];
                setVulns(mapped);
              }
            } catch (e) {
              // Fall back silently if details endpoint fails
            }
            
            // Compute a fixed duration for completed scans
            let durationSec: number | null = null;
            if (typeof lastScan.total_time === 'number' && !isNaN(lastScan.total_time)) {
              durationSec = Math.max(0, Math.floor(lastScan.total_time));
            } else if (lastScan.created_at && lastScan.updated_at) {
              try {
                const created = new Date(lastScan.created_at).getTime();
                const updated = new Date(lastScan.updated_at).getTime();
                if (!isNaN(created) && !isNaN(updated) && updated >= created) {
                  durationSec = Math.floor((updated - created) / 1000);
                }
              } catch {}
            }

            if (durationSec !== null) {
              setHistoryDurationSec(durationSec);
              const hours = Math.floor(durationSec / 3600);
              const minutes = Math.floor((durationSec % 3600) / 60);
              const seconds = durationSec % 60;
              setElapsedTime(`${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
              // Ensure we don't start a ticking interval for history view
              setStartTime(null);
            }
            
            // Load scan logs if available
            try {
              // Keep compatibility: if details not available, use generic logs endpoint
              if (scanLogs.length === 0) {
                const logsResponse = await apiService.getScanLogs();
                const formattedLogs: ScanLog[] = logsResponse.logs.map((log: any) => ({
                  id: log.id || Math.random().toString(36).substr(2, 9),
                  timestamp: new Date(log.timestamp),
                  level: (log.level || 'info') as ScanLog['level'],
                  phase: log.phase || 'general',
                  message: log.message
                }));
                setScanLogs(formattedLogs);
              }
            } catch (error) {
              console.error('Failed to load scan logs:', error);
            }
          }
        } catch (error) {
          console.error('Failed to load scan history:', error);
        }
      }
    };

    loadScanHistory();
  }, [isOpen, scanStatus.is_scanning]);

  // Timer: only tick during active scans
  useEffect(() => {
    // Prefer backend start_time if available, otherwise use local time when scanning begins
    if (!startTime && scanStatus.start_time && scanStatus.is_scanning) {
      setStartTime(new Date(scanStatus.start_time));
    } else if (!startTime && isOpen && scanStatus.is_scanning) {
      setStartTime(new Date());
    }

    const computeAndSet = () => {
      if (!startTime) return;
      const now = new Date();
      const diff = now.getTime() - startTime.getTime();
      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);
      setElapsedTime(`${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
    };

    if (scanStatus.is_scanning) {
      computeAndSet();
    }

    // Tick only while actively scanning
    let interval: NodeJS.Timeout | null = null;
    if (startTime && scanStatus.is_scanning) {
      interval = setInterval(computeAndSet, 1000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [startTime, scanStatus.start_time, scanStatus.is_scanning, isOpen]);

  // Attempt to restore persisted state when opening during an active scan
  useEffect(() => {
    if (isOpen && scanStatus.is_scanning) {
      tryRestoreState();
    }
  }, [isOpen, scanStatus.is_scanning, scanStatus.scan_id]);

  // While scanning, also fetch current backend logs/vulns on open to backfill gaps
  useEffect(() => {
    if (!(isOpen && scanStatus.is_scanning)) return;
    (async () => {
      try {
        const logsResponse = await apiService.getScanLogs();
        if (Array.isArray(logsResponse.logs)) {
          const fetched: ScanLog[] = logsResponse.logs.map((log: any) => ({
            id: log.id || Math.random().toString(36).substr(2, 9),
            timestamp: new Date(log.timestamp),
            level: (log.level || 'info') as ScanLog['level'],
            phase: log.phase || 'general',
            message: log.message,
          }));
          // Merge with existing and dedupe by message+timestamp
          const keyOf = (l: ScanLog) => `${l.message}|${l.timestamp instanceof Date ? l.timestamp.toISOString() : l.timestamp}`;
          const map = new Map<string, ScanLog>();
          [...fetched, ...scanLogs].forEach(l => map.set(keyOf(l), l));
          const merged = Array.from(map.values()).sort((a, b) => (new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
          setScanLogs(merged.slice(0, 500));
        }
      } catch {}
      try {
        const vres = await apiService.getVulnerabilitiesWithFallback();
        setVulns(vres.vulnerabilities);
      } catch {}
      // Persist merged state
      saveState();
    })();
  }, [isOpen, scanStatus.is_scanning]);

  // Persist state whenever key pieces change (only while monitor is open)
  useEffect(() => {
    if (!isOpen) return;
    saveState();
  }, [isOpen, startTime, scanLogs, urlsFound, currentUrl, currentPayload, vulns, scanStatus.scan_id]);

  // Reset timer when scan stops or monitor closes
  useEffect(() => {
    if (!scanStatus.is_scanning && startTime && scanStatus.phase === 'completed') {
      // Keep the timer running for completed scans to show total time
    } else if (!isOpen) {
      // Reset everything when monitor is closed
      setStartTime(null);
      setElapsedTime('00:00:00');
      setScanLogs([]);
      setCurrentUrl('');
      setCurrentPayload('');
    }
  }, [scanStatus.is_scanning, isOpen]);

  // WebSocket integration for real-time logs
  useEffect(() => {
    if (!isOpen) return;

    // Connect to WebSocket for real-time updates
    const wsUrl = 'ws://localhost:8000/ws/scan-updates';
    let ws: WebSocket;

    try {
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('[WS] Connected to scan monitoring WebSocket');
      };
      
  ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log('[WS] Received:', data);
          
          // Handle different message types from our real-time scanner
          switch (data.type) {
            case 'log':
              // Real-time verbose log message
              const log: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(data.timestamp * 1000), // Convert from timestamp
                level: data.level as ScanLog['level'],
                phase: data.phase || 'scanning',
                message: data.message,
                details: {
                  current_url: data.current_url,
                  current_payload: data.current_payload
                }
              };
              setScanLogs(prev => [log, ...prev].slice(0, 500));
              
              // Update current URL and payload
              if (data.current_url) {
                setCurrentUrl(data.current_url);
                setUrlsFound(prev => {
                  const set = new Set(prev);
                  set.add(data.current_url);
                  return Array.from(set);
                });
              }
              if (data.current_payload) setCurrentPayload(data.current_payload);
              // Persist after updates
              saveState();
              break;
              
            case 'phase_update':
              // Phase change notification
              const phaseLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'info',
                phase: data.phase,
                message: `Entering ${data.phase} phase (${data.progress}% complete)`
              };
              setScanLogs(prev => [phaseLog, ...prev].slice(0, 500));
              saveState();
              break;
              
            case 'url_crawled':
              // URL discovery log
              const urlLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'info',
                phase: 'crawling',
                message: `Discovered URL: ${data.url} (depth ${data.depth}) - Total: ${data.total_urls}`
              };
              setScanLogs(prev => [urlLog, ...prev].slice(0, 500));
              setCurrentUrl(data.url);
              setUrlsFound(prev => {
                const set = new Set(prev);
                set.add(data.url);
                return Array.from(set);
              });
              saveState();
              break;
              
            case 'form_found':
              // Form discovery log
              const formLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'info',
                phase: 'crawling',
                message: `Found form: ${data.form.action} (${data.form.method}) - Total: ${data.total_forms}`
              };
              setScanLogs(prev => [formLog, ...prev].slice(0, 500));
              saveState();
              break;
              
            case 'payload_testing':
              // Payload testing log
              const payloadLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'info',
                phase: 'scanning',
                message: `Testing ${data.scanner} payload: ${data.payload} on ${data.parameter}@${data.url}`
              };
              setScanLogs(prev => [payloadLog, ...prev].slice(0, 500));
              setCurrentUrl(data.url);
              setCurrentPayload(data.payload);
              if (data.url) {
                setUrlsFound(prev => {
                  const set = new Set(prev);
                  set.add(data.url);
                  return Array.from(set);
                });
              }
              saveState();
              break;
              
            case 'vulnerability_found':
              // Vulnerability discovery log
              const vulnLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'warning',
                phase: 'scanning',
                message: `🚨 ${data.vulnerability.type} vulnerability found in ${data.vulnerability.parameter}@${data.vulnerability.url}`,
                details: data.vulnerability
              };
              setScanLogs(prev => [vulnLog, ...prev].slice(0, 500));
              // Refresh local vulnerabilities from live cache
              apiService.getVulnerabilitiesWithFallback().then(res => { setVulns(res.vulnerabilities); saveState(); }).catch(() => {});
              break;
              
            case 'scan_complete':
              // Scan completion log
              const completeLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'success',
                phase: 'completed',
                message: `✅ Scan completed! Found ${data.vulnerabilities_found} vulnerabilities`
              };
              setScanLogs(prev => [completeLog, ...prev].slice(0, 500));
              // Final refresh of vulnerabilities
              apiService.getVulnerabilitiesWithFallback().then(res => { setVulns(res.vulnerabilities); saveState(); }).catch(() => {});
              break;
              
            case 'scan_error':
              // Scan error log
              const errorLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(),
                level: 'error',
                phase: 'error',
                message: `❌ Scan error: ${data.error}`
              };
              setScanLogs(prev => [errorLog, ...prev].slice(0, 500));
              saveState();
              break;
              
            case 'scan_log':
              // Legacy scan log handling (for compatibility)
              const legacyLog: ScanLog = {
                id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date(data.data.timestamp),
                level: data.data.message.toLowerCase().includes('error') ? 'error' : 
                       data.data.message.toLowerCase().includes('vulnerability') ? 'warning' :
                       data.data.message.toLowerCase().includes('completed') ? 'success' : 'info',
                phase: data.data.phase,
                message: data.data.message
              };
              setScanLogs(prev => [legacyLog, ...prev].slice(0, 500));
              saveState();
              break;
              
            case 'scan_progress':
              // Handle progress updates if needed
              console.log('[WS] Progress update:', data.data);
              break;
              
            default:
              console.log('[WS] Unknown message type:', data.type);
          }
        } catch (error) {
          console.error('[WS] Error parsing message:', error);
        }
      };
      
      ws.onerror = (error) => {
        console.error('[WS] WebSocket error:', error);
      };
      
      ws.onclose = () => {
        console.log('[WS] WebSocket connection closed');
      };
    } catch (error) {
      console.error('[WS] Failed to connect to WebSocket:', error);
    }

    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, [isOpen]);

  // Initialize local vulnerabilities on open
  useEffect(() => {
    if (!isOpen) return;
    (async () => {
      try {
        const res = await apiService.getVulnerabilitiesWithFallback();
        setVulns(res.vulnerabilities);
      } catch {}
    })();
  }, [isOpen]);

  // Update current URL and payload from backend (keep existing logic)
  useEffect(() => {
    if (scanStatus.current_url) {
      setCurrentUrl(scanStatus.current_url);
    }
    if (scanStatus.current_payload) {
      setCurrentPayload(scanStatus.current_payload);
    }
  }, [scanStatus.current_url, scanStatus.current_payload]);

  const handleStopScan = async () => {
    try {
      await stopScan();
      setScanLogs(prev => [{
        id: Math.random().toString(36).substr(2, 9),
        timestamp: new Date(),
        level: 'warning',
        phase: 'Stopped',
        message: 'Scan stopped by user'
      }, ...prev]);
  // Persist stop state too
  saveState();
    } catch (error) {
      console.error('Failed to stop scan:', error);
    }
  };

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'crawling': return <Globe className="h-4 w-4" />;
      case 'scanning': return <Bug className="h-4 w-4" />;
      case 'ai_analysis': return <Brain className="h-4 w-4" />;
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const getLogIcon = (level: ScanLog['level']) => {
    switch (level) {
      case 'info': return <Info className="h-4 w-4 text-blue-500" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
    }
  };

  const getStatusColor = () => {
    if (!scanStatus.is_scanning) return 'bg-gray-500';
    switch (scanStatus.phase) {
      case 'crawling': return 'bg-blue-500';
      case 'scanning': return 'bg-orange-500';
      case 'ai_analysis': return 'bg-purple-500';
      case 'completed': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Scan Monitor{scanRequest?.target_url ? ` - ${scanRequest.target_url}` : ''}
          </DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-[70vh]">
          {/* Left Panel - Status Overview */}
          <div className="lg:col-span-1 space-y-4">
            {/* Timer and Status */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Scan Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${getStatusColor()} animate-pulse`} />
                  <span className="text-sm font-medium capitalize">
                    {scanStatus.is_scanning ? scanStatus.phase : 'Idle'}
                  </span>
                </div>
                
                <div className="text-center">
                  <div className="text-2xl font-mono font-bold">{elapsedTime}</div>
                  <div className="text-xs text-muted-foreground">Elapsed Time</div>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between text-xs">
                    <span>Progress</span>
                    <span>{scanStatus.progress}%</span>
                  </div>
                  <Progress value={scanStatus.progress} className="h-2" />
                </div>

                <div className="flex gap-2">
                  {scanStatus.is_scanning ? (
                    <Button size="sm" variant="destructive" onClick={handleStopScan} className="flex-1">
                      <Square className="h-3 w-3 mr-1" />
                      Stop
                    </Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={onClose} className="flex-1">
                      Close
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Current Activity */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Target className="h-4 w-4" />
                  Current Activity
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {currentUrl && (
                  <div>
                    <div className="text-xs text-muted-foreground mb-1">Current URL</div>
                    <div className="text-xs font-mono bg-muted p-2 rounded break-all">
                      {currentUrl}
                    </div>
                  </div>
                )}
                
                {currentPayload && (
                  <div>
                    <div className="text-xs text-muted-foreground mb-1">Current Payload</div>
                    <div className="text-xs font-mono bg-muted p-2 rounded break-all">
                      {currentPayload}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Statistics */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  Statistics
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-muted p-2 rounded text-center">
                    <div className="font-mono font-bold">{scanStatus.stats.urls_crawled}</div>
                    <div className="text-muted-foreground">URLs</div>
                  </div>
                  <div className="bg-muted p-2 rounded text-center">
                    <div className="font-mono font-bold">{scanStatus.stats.forms_found}</div>
                    <div className="text-muted-foreground">Forms</div>
                  </div>
                  <div className="bg-muted p-2 rounded text-center">
                    <div className="font-mono font-bold">{scanStatus.stats.requests_sent}</div>
                    <div className="text-muted-foreground">Requests</div>
                  </div>
                  <div className="bg-muted p-2 rounded text-center">
                    <div className="font-mono font-bold text-red-500">{scanStatus.stats.vulnerabilities_found}</div>
                    <div className="text-muted-foreground">Vulns</div>
                  </div>
                </div>
                
                {scanRequest.ai_calls > 0 && (
                  <div className="bg-muted p-2 rounded text-center">
                    <div className="font-mono font-bold text-purple-500">{scanStatus.stats.ai_calls_made}</div>
                    <div className="text-muted-foreground text-xs">AI Calls Made</div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right Panel - Logs and Details */}
          <div className="lg:col-span-2">
            <Tabs defaultValue="logs" className="h-full flex flex-col">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="logs">Live Logs</TabsTrigger>
                <TabsTrigger value="urls">URLs Found</TabsTrigger>
                <TabsTrigger value="vulns">Vulnerabilities</TabsTrigger>
              </TabsList>
              
              <TabsContent value="logs" className="flex-1 mt-4">
                <Card className="h-full">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Real-time Scan Logs</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <ScrollArea className="h-[400px] p-4">
                      <div className="space-y-2">
                        {scanLogs.map((log) => (
                          <div key={log.id} className="flex items-start gap-2 text-xs p-2 rounded border">
                            {getLogIcon(log.level)}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant="outline" className="text-xs">
                                  {log.phase}
                                </Badge>
                                <span className="text-muted-foreground">
                                  {log.timestamp.toLocaleTimeString()}
                                </span>
                              </div>
                              <div className="font-mono break-all">{log.message}</div>
                              {log.details && (
                                <div className="text-muted-foreground mt-1">
                                  {JSON.stringify(log.details, null, 2)}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                        
                        {scanLogs.length === 0 && (
                          <div className="text-center text-muted-foreground py-8">
                            No logs yet. Start a scan to see real-time progress.
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="urls" className="flex-1 mt-4">
                <Card className="h-full">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Discovered URLs</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <ScrollArea className="h-[400px] p-4">
                      <div className="space-y-1">
                        {urlsFound.slice(-50).map((url, i) => (
                          <div key={`${url}-${i}`} className="text-xs font-mono p-2 bg-muted rounded">
                            {url}
                          </div>
                        ))}

                        {urlsFound.length === 0 && (
                          <div className="text-center text-muted-foreground py-8">
                            No URLs discovered yet.
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="vulns" className="flex-1 mt-4">
                <Card className="h-full">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Vulnerabilities Found</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <ScrollArea className="h-[400px] p-4">
                      <div className="space-y-2">
                        {vulns.map((v, i) => (
                          <div key={v.id || i} className="p-3 border rounded">
                            <div className="flex items-center gap-2 mb-2">
                              <AlertTriangle className="h-4 w-4 text-red-500" />
                              <Badge variant="destructive">{(v.severity || 'Medium').toString()}</Badge>
                              <span className="text-sm font-medium">{v.type?.toUpperCase()} vulnerability</span>
                            </div>
                            <div className="text-xs text-muted-foreground space-y-1">
                              <div>URL: <span className="font-mono break-all">{v.url}</span></div>
                              {v.parameter && <div>Parameter: <span className="font-mono">{v.parameter}</span></div>}
                              {v.payload && <div>Payload: <span className="font-mono break-all">{v.payload}</span></div>}
                            </div>
                          </div>
                        ))}

                        {vulns.length === 0 && (
                          <div className="text-center text-muted-foreground py-8">
                            <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-500" />
                            No vulnerabilities found yet.
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
