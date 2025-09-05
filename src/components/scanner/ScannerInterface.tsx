import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ScanLogs } from './ScanLogs_new';
import { ScanMonitor } from './ScanMonitor';
import { useScan } from '@/hooks/useScan';
import { ScanRequest } from '@/lib/api';
import { 
  Target, 
  Settings, 
  Brain, 
  Shield, 
  Globe,
  ChevronDown,
  Play,
  Clock,
  Zap,
  Cpu,
  Monitor
} from 'lucide-react';

export function ScannerInterface() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanTypes, setScanTypes] = useState({
    xss: true,
    sqli: true,
    csrf: true,
    security_misconfiguration: false,
    vulnerable_components: false,
    ssrf: false
  });
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [oastEnabled, setOastEnabled] = useState(false);
  const [verboseEnabled, setVerboseEnabled] = useState(true);
  const [headlessMode, setHeadlessMode] = useState(false);
  const [scanMode, setScanMode] = useState<'fast' | 'full'>('fast');
  const [maxAiCalls, setMaxAiCalls] = useState(30);
  const [requestDelay, setRequestDelay] = useState(100);
  const [showScanMonitor, setShowScanMonitor] = useState(false);
  const [currentScanRequest, setCurrentScanRequest] = useState<ScanRequest | null>(null);

  // Use the scan hook
  const { startScan, scanStatus, isConnected } = useScan();

  const handleScanTypeChange = (type: string, checked: boolean) => {
    setScanTypes(prev => ({ ...prev, [type]: checked }));
  };

  const handleStartScan = async () => {
    if (!targetUrl) return;

    const selectedScanTypes = Object.entries(scanTypes)
      .filter(([_, enabled]) => enabled)
      .map(([type, _]) => type);

    if (selectedScanTypes.length === 0) {
      alert('Please select at least one scan type');
      return;
    }

    const scanRequest: ScanRequest = {
      target_url: targetUrl,
      scan_types: selectedScanTypes,
      mode: scanMode,
      headless: headlessMode,
      oast: oastEnabled,
      ai_calls: aiEnabled ? maxAiCalls : 0,
      verbose: verboseEnabled, // Use the verbose setting from UI
      max_depth: 3,
      delay: requestDelay
    };

    try {
      // Show the monitor immediately, unless in headless mode
      if (!headlessMode) {
        setShowScanMonitor(true);
      }
      setCurrentScanRequest(scanRequest);
      await startScan(scanRequest);
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-3 bg-gradient-primary rounded-lg shadow-glow-primary">
          <Target className="h-6 w-6 text-primary-foreground" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Vulnerability Scanner</h1>
          <p className="text-muted-foreground">Configure and launch security scans</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Configuration */}
        <div className="lg:col-span-2 space-y-6">
          {/* Target Configuration */}
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="text-lg text-foreground flex items-center gap-2">
                <Target className="h-5 w-5 text-primary" />
                Target Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target-url" className="text-foreground">Target URL</Label>
                <Input
                  id="target-url"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="font-mono bg-input border-border text-foreground"
                />
                <p className="text-xs text-muted-foreground">
                  Enter the target URL to scan for vulnerabilities
                </p>
              </div>

              {/* Recent Targets */}
              <div className="space-y-2">
                <Label className="text-foreground">Recent Targets</Label>
                <div className="flex flex-wrap gap-2">
                  {['https://example.com', 'https://test.local', 'https://staging.app'].map((url) => (
                    <Badge 
                      key={url} 
                      variant="outline" 
                      className="cursor-pointer hover:bg-secondary/50 font-mono text-xs"
                      onClick={() => setTargetUrl(url)}
                    >
                      {url}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Scan Configuration */}
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="text-lg text-foreground flex items-center gap-2">
                <Settings className="h-5 w-5 text-primary" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="types" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="types">Scan Types</TabsTrigger>
                  <TabsTrigger value="modes">Scan Modes</TabsTrigger>
                  <TabsTrigger value="advanced">Advanced</TabsTrigger>
                </TabsList>

                <TabsContent value="types" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    {[
                      { id: 'xss', label: 'Cross-Site Scripting (XSS)', color: 'severity-high' },
                      { id: 'sqli', label: 'SQL Injection', color: 'severity-critical' },
                      { id: 'csrf', label: 'CSRF Vulnerabilities', color: 'severity-medium' },
                      { id: 'security_misconfiguration', label: 'Security Misconfiguration', color: 'severity-high' },
                      { id: 'vulnerable_components', label: 'Vulnerable Components', color: 'severity-critical' },
                      { id: 'ssrf', label: 'Server-Side Request Forgery', color: 'severity-high' }
                    ].map((scanType) => (
                      <div key={scanType.id} className="flex items-center space-x-2 p-3 rounded-lg border border-border hover:bg-secondary/20">
                        <Checkbox
                          id={scanType.id}
                          checked={scanTypes[scanType.id] || false}
                          onCheckedChange={(checked) => handleScanTypeChange(scanType.id, checked === true)}
                        />
                        <div className="flex-1">
                          <Label htmlFor={scanType.id} className="text-foreground cursor-pointer">
                            {scanType.label}
                          </Label>
                          <div className={`w-2 h-2 rounded-full bg-${scanType.color} mt-1`}></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="modes" className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card 
                      className={`bg-card border-border hover:shadow-glow-primary transition-all cursor-pointer ${scanMode === 'fast' ? 'ring-2 ring-primary' : ''}`}
                    >
                      <CardContent className="p-4">
                        <div 
                          className="flex items-center gap-3 mb-3"
                          onClick={() => setScanMode('fast')}
                        >
                          <Zap className="h-5 w-5 text-status-warning" />
                          <div>
                            <h3 className="font-medium text-foreground">Fast Scan</h3>
                            <p className="text-sm text-muted-foreground">Quick scan with limited payloads</p>
                          </div>
                        </div>
                        <Button 
                          size="sm" 
                          variant="outline" 
                          className="w-full"
                          disabled={!targetUrl || scanStatus.is_scanning}
                          onClick={(e) => {
                            e.stopPropagation();
                            setScanMode('fast');
                            handleStartScan();
                          }}
                        >
                          <Play className="h-3 w-3 mr-1" />
                          Start Fast Scan
                        </Button>
                      </CardContent>
                    </Card>

                    <Card 
                      className={`bg-card border-border hover:shadow-glow-primary transition-all cursor-pointer ${scanMode === 'full' ? 'ring-2 ring-primary' : ''}`}
                    >
                      <CardContent className="p-4">
                        <div 
                          className="flex items-center gap-3 mb-3"
                          onClick={() => setScanMode('full')}
                        >
                          <Cpu className="h-5 w-5 text-status-scanning" />
                          <div>
                            <h3 className="font-medium text-foreground">Full Scan</h3>
                            <p className="text-sm text-muted-foreground">Comprehensive scan with all payloads</p>
                          </div>
                        </div>
                        <Button 
                          size="sm" 
                          variant="outline" 
                          className="w-full"
                          disabled={!targetUrl || scanStatus.is_scanning}
                          onClick={(e) => {
                            e.stopPropagation();
                            setScanMode('full');
                            handleStartScan();
                          }}
                        >
                          <Play className="h-3 w-3 mr-1" />
                          Start Full Scan
                        </Button>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="advanced" className="space-y-4">
                  <Collapsible open={advancedOpen} onOpenChange={setAdvancedOpen}>
                    <CollapsibleTrigger className="flex items-center gap-2 text-foreground">
                      <ChevronDown className="h-4 w-4" />
                      Advanced Options
                    </CollapsibleTrigger>
                    <CollapsibleContent className="space-y-4 mt-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label className="text-foreground">Request Delay (ms)</Label>
                          <Input 
                            value={requestDelay} 
                            onChange={(e) => setRequestDelay(Number(e.target.value))}
                            type="number" 
                          />
                        </div>
                        <div className="space-y-2">
                          <Label className="text-foreground">Max Concurrent</Label>
                          <Input defaultValue="5" type="number" />
                        </div>
                      </div>
                    </CollapsibleContent>
                  </Collapsible>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* Side Panel */}
        <div className="space-y-6">
          {/* AI Configuration */}
          <Card className="bg-gradient-ai border-border">
            <CardHeader>
              <CardTitle className="text-lg text-foreground flex items-center gap-2">
                <Brain className="h-5 w-5 text-ai-primary" />
                AI Enhancement
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="ai-enabled"
                  checked={aiEnabled}
                  onCheckedChange={(checked) => setAiEnabled(checked === true)}
                />
                <Label htmlFor="ai-enabled" className="text-foreground">
                  Enable AI Analysis
                </Label>
              </div>
              
              {aiEnabled && (
                <div className="space-y-3">
                  <div className="p-3 bg-secondary/20 rounded-lg">
                    <p className="text-sm text-foreground">Groq qwen/qwen3-32b</p>
                    <p className="text-xs text-muted-foreground">Enhanced vulnerability analysis</p>
                  </div>
                  
                  <div className="space-y-2">
                    <Label className="text-foreground">Max AI Calls</Label>
                    <Input 
                      value={maxAiCalls} 
                      onChange={(e) => setMaxAiCalls(Number(e.target.value))}
                      type="number" 
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* OAST Configuration */}
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="text-lg text-foreground flex items-center gap-2">
                <Globe className="h-5 w-5 text-primary" />
                OAST (Out-of-Band Testing)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="oast-enabled"
                  checked={oastEnabled}
                  onCheckedChange={(checked) => setOastEnabled(checked === true)}
                />
                <Label htmlFor="oast-enabled" className="text-foreground">
                  Enable OAST Testing
                </Label>
              </div>
              
              {oastEnabled && (
                <div className="p-3 bg-secondary/20 rounded-lg">
                  <p className="text-sm text-foreground">Blind Vulnerability Detection</p>
                  <p className="text-xs text-muted-foreground">
                    Detects blind XSS, SQL injection, and command injection vulnerabilities
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan Options */}
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="text-lg text-foreground flex items-center gap-2">
                <Monitor className="h-5 w-5 text-primary" />
                Scan Options
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="verbose-enabled"
                  checked={verboseEnabled}
                  onCheckedChange={(checked) => setVerboseEnabled(checked === true)}
                />
                <Label htmlFor="verbose-enabled" className="text-foreground">
                  Verbose Logging
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="headless-mode"
                  checked={headlessMode}
                  onCheckedChange={(checked) => setHeadlessMode(checked === true)}
                />
                <Label htmlFor="headless-mode" className="text-foreground">
                  Headless Mode
                </Label>
              </div>
              
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">
                  Verbose logging provides detailed real-time scan information. 
                  Headless mode runs scans without opening the monitor window.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Real-time Scan Logs */}
          {scanStatus.is_scanning && (
            <Card className="bg-gradient-security border-border">
              <CardHeader>
                <CardTitle className="text-lg text-foreground flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-primary" />
                  Scan Logs
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScanLogs isScanning={scanStatus.is_scanning} />
              </CardContent>
            </Card>
          )}

          {/* Quick Actions */}
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="text-lg text-foreground flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Quick Actions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button 
                variant="scanner" 
                className="w-full" 
                disabled={!targetUrl || scanStatus.is_scanning}
                onClick={handleStartScan}
              >
                <Play className="h-4 w-4 mr-2" />
                {scanStatus.is_scanning ? 'Scanning...' : 'Start Security Scan'}
              </Button>
              
              {/* Monitor button - shown when scan is running or completed */}
              {(scanStatus.is_scanning || currentScanRequest) && (
                <Button 
                  variant="outline" 
                  className="w-full" 
                  onClick={() => setShowScanMonitor(true)}
                >
                  <Monitor className="h-4 w-4 mr-2" />
                  {scanStatus.is_scanning ? 'Monitor Scan Progress' : 'View Last Scan'}
                </Button>
              )}
              
              <Button variant="outline" className="w-full">
                <Clock className="h-4 w-4 mr-2" />
                Schedule Scan
              </Button>
              
              <div className="pt-3 border-t border-border">
                <p className="text-xs text-muted-foreground">
                  Estimated scan time: 15-30 minutes
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Backend: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
                </p>
                {scanStatus.is_scanning && (
                  <p className="text-xs text-primary mt-1 font-medium">
                    📊 Scan Monitor available - Click to view progress
                  </p>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Scan Presets */}
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="text-sm text-foreground">Scan Presets</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {['Web Application', 'API Endpoint', 'CMS Security', 'Custom Config'].map((preset) => (
                <Button 
                  key={preset} 
                  variant="ghost" 
                  className="w-full justify-start text-sm"
                >
                  {preset}
                </Button>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Scan Monitor Dialog */}
      {currentScanRequest && (
        <ScanMonitor
          isOpen={showScanMonitor}
          onClose={() => setShowScanMonitor(false)}
          scanRequest={currentScanRequest}
        />
      )}
    </div>
  );
}