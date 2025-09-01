import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { 
  Target, 
  Settings, 
  Brain, 
  Shield, 
  ChevronDown,
  Play,
  Clock,
  Zap,
  Cpu
} from 'lucide-react';

export function ScannerInterface() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanTypes, setScanTypes] = useState({
    xss: true,
    sqli: true,
    csrf: false,
    lfi: false,
    rfi: false
  });
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(true);

  const handleScanTypeChange = (type: string, checked: boolean) => {
    setScanTypes(prev => ({ ...prev, [type]: checked }));
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
                      { id: 'lfi', label: 'Local File Inclusion', color: 'severity-high' },
                      { id: 'rfi', label: 'Remote File Inclusion', color: 'severity-critical' },
                      { id: 'xxe', label: 'XML External Entity', color: 'severity-medium' }
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
                    <Card className="bg-card border-border hover:shadow-glow-primary transition-all cursor-pointer">
                      <CardContent className="p-4">
                        <div className="flex items-center gap-3">
                          <Zap className="h-5 w-5 text-status-warning" />
                          <div>
                            <h3 className="font-medium text-foreground">Fast Scan</h3>
                            <p className="text-sm text-muted-foreground">Quick scan with limited payloads</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card className="bg-card border-border hover:shadow-glow-primary transition-all cursor-pointer">
                      <CardContent className="p-4">
                        <div className="flex items-center gap-3">
                          <Cpu className="h-5 w-5 text-status-scanning" />
                          <div>
                            <h3 className="font-medium text-foreground">Full Scan</h3>
                            <p className="text-sm text-muted-foreground">Comprehensive scan with all payloads</p>
                          </div>
                        </div>
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
                          <Input defaultValue="100" type="number" />
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
                    <Input defaultValue="100" type="number" />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

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
                disabled={!targetUrl}
              >
                <Play className="h-4 w-4 mr-2" />
                Start Security Scan
              </Button>
              
              <Button variant="outline" className="w-full">
                <Clock className="h-4 w-4 mr-2" />
                Schedule Scan
              </Button>
              
              <div className="pt-3 border-t border-border">
                <p className="text-xs text-muted-foreground">
                  Estimated scan time: 15-30 minutes
                </p>
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
    </div>
  );
}