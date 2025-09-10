import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Server, 
  Activity, 
  Globe, 
  Shield, 
  TrendingUp, 
  RefreshCw,
  Trash2,
  Copy,
  Eye,
  AlertTriangle,
  CheckCircle,
  XCircle
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { apiService, OASTStatus, OASTConfig, OASTPayload, OASTCallback } from '@/lib/api';

export const OASTManager: React.FC = () => {
  const [oastStatus, setOastStatus] = useState<OASTStatus | null>(null);
  const [config, setConfig] = useState<OASTConfig>({
    collaborator_url: 'http://localhost:8001',
    auth_token: '',
    enabled: true
  });
  const [payloads, setPayloads] = useState<OASTPayload[]>([]);
  const [callbacks, setCallbacks] = useState<OASTCallback[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const { toast } = useToast();

  useEffect(() => {
    loadOASTStatus();
    loadPayloads();
    loadCallbacks();
  }, []);

  const loadOASTStatus = async () => {
    try {
      const status = await apiService.getOASTStatus();
      setOastStatus(status);
    } catch (error) {
      console.error('Failed to load OAST status:', error);
    }
  };

  const loadPayloads = async () => {
    try {
      const response = await apiService.getOASTPayloads();
      setPayloads(response.payloads);
    } catch (error) {
      console.error('Failed to load OAST payloads:', error);
    }
  };

  const loadCallbacks = async () => {
    try {
      const response = await apiService.getOASTCallbacks();
      setCallbacks(response.callbacks);
    } catch (error) {
      console.error('Failed to load OAST callbacks:', error);
    }
  };

  const handleConfigureOAST = async () => {
    setLoading(true);
    try {
      await apiService.configureOAST(config);
      await loadOASTStatus();
      toast({
        title: "OAST Configured",
        description: "OAST collaborator has been configured successfully.",
      });
    } catch (error) {
      toast({
        title: "Configuration Failed",
        description: error instanceof Error ? error.message : "Failed to configure OAST",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleGeneratePayloads = async (vulnerabilityType: string) => {
    setLoading(true);
    try {
      await apiService.generateOASTPayloads(vulnerabilityType);
      await loadPayloads();
      toast({
        title: "Payloads Generated",
        description: `Generated ${vulnerabilityType.toUpperCase()} OAST payloads successfully.`,
      });
    } catch (error) {
      toast({
        title: "Generation Failed",
        description: error instanceof Error ? error.message : "Failed to generate payloads",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCleanup = async () => {
    setLoading(true);
    try {
      const result = await apiService.cleanupOAST();
      await loadOASTStatus();
      await loadPayloads();
      await loadCallbacks();
      toast({
        title: "Cleanup Complete",
        description: result.message,
      });
    } catch (error) {
      toast({
        title: "Cleanup Failed",
        description: error instanceof Error ? error.message : "Failed to cleanup OAST data",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Text copied to clipboard",
    });
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getVulnTypeColor = (type: string) => {
    switch (type) {
      case 'xss': return 'bg-red-100 text-red-800';
      case 'sqli': return 'bg-blue-100 text-blue-800';
      case 'command_injection': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">OAST Manager</h2>
          <p className="text-muted-foreground">
            Manage Out-of-Band Application Security Testing
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => {
              loadOASTStatus();
              loadPayloads();
              loadCallbacks();
            }}
            disabled={loading}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button
            variant="outline"
            onClick={handleCleanup}
            disabled={loading}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Cleanup
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
          <TabsTrigger value="payloads">Payloads</TabsTrigger>
          <TabsTrigger value="callbacks">Callbacks</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Status</CardTitle>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="flex items-center space-x-2">
                  {oastStatus?.status === 'active' ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm text-green-600">Active</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-red-500" />
                      <span className="text-sm text-red-600">Inactive</span>
                    </>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {oastStatus?.collaborator_url || 'Not configured'}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Payloads</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {oastStatus?.statistics.total_payloads || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  {oastStatus?.statistics.active_payloads || 0} active
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Callbacks</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {oastStatus?.statistics.total_callbacks || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  Total interactions received
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Vulnerability %</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {oastStatus?.statistics.vulnerability_percentage || 0}%
                </div>
              </CardContent>
            </Card>
          </div>

          {oastStatus?.statistics.vulnerability_types && (
            <Card>
              <CardHeader>
                <CardTitle>Vulnerability Types</CardTitle>
                <CardDescription>
                  Breakdown by vulnerability type
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(oastStatus.statistics.vulnerability_types).map(([type, stats]) => (
                    <div key={type} className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Badge className={getVulnTypeColor(type)}>
                          {type.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {stats.payloads} payloads, {stats.callbacks} callbacks
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="configuration" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>OAST Configuration</CardTitle>
              <CardDescription>
                Configure your OAST collaborator settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4">
                <div className="space-y-2">
                  <Label htmlFor="collaborator_url">Collaborator URL</Label>
                  <Input
                    id="collaborator_url"
                    placeholder="http://localhost:8001"
                    value={config.collaborator_url}
                    onChange={(e) => setConfig({ ...config, collaborator_url: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="auth_token">Authentication Token (Optional)</Label>
                  <Input
                    id="auth_token"
                    type="password"
                    placeholder="Enter auth token if required"
                    value={config.auth_token}
                    onChange={(e) => setConfig({ ...config, auth_token: e.target.value })}
                  />
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="enabled"
                    checked={config.enabled}
                    onCheckedChange={(checked) => setConfig({ ...config, enabled: checked })}
                  />
                  <Label htmlFor="enabled">Enable OAST</Label>
                </div>
              </div>

              <Button onClick={handleConfigureOAST} disabled={loading}>
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Configuring...
                  </>
                ) : (
                  'Configure OAST'
                )}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Generate Payloads</CardTitle>
              <CardDescription>
                Generate OAST payloads for different vulnerability types
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => handleGeneratePayloads('xss')}
                  disabled={loading}
                >
                  Generate XSS Payloads
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleGeneratePayloads('sqli')}
                  disabled={loading}
                >
                  Generate SQLi Payloads
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleGeneratePayloads('command_injection')}
                  disabled={loading}
                >
                  Generate Command Injection
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="payloads" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>OAST Payloads</CardTitle>
              <CardDescription>
                Generated payloads waiting for callbacks ({payloads.length} total)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {payloads.map((payload) => (
                  <div key={payload.id} className="border rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Badge className={getVulnTypeColor(payload.vulnerability_type)}>
                          {payload.vulnerability_type.toUpperCase()}
                        </Badge>
                        {payload.has_callback && (
                          <Badge className="bg-green-100 text-green-800">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Callback Received
                          </Badge>
                        )}
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(payload.payload)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    
                    <div className="font-mono text-sm bg-gray-50 p-2 rounded break-all">
                      {payload.payload}
                    </div>
                    
                    <div className="text-xs text-muted-foreground">
                      Callback URL: {payload.callback_url}
                    </div>
                    
                    <div className="text-xs text-muted-foreground">
                      Created: {formatTimestamp(payload.created_at)} | 
                      Expires: {formatTimestamp(payload.expires_at)}
                    </div>
                  </div>
                ))}
                
                {payloads.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    No payloads generated yet. Generate some payloads in the Configuration tab.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="callbacks" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>OAST Callbacks</CardTitle>
              <CardDescription>
                Received callbacks indicating potential vulnerabilities ({callbacks.length} total)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {callbacks.map((callback) => (
                  <div key={callback.id} className="border rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Badge className={getVulnTypeColor(callback.vulnerability_type)}>
                          {callback.vulnerability_type.toUpperCase()}
                        </Badge>
                        <Badge variant="outline">
                          {callback.method}
                        </Badge>
                        <AlertTriangle className="h-4 w-4 text-orange-500" />
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {formatTimestamp(callback.timestamp)}
                      </div>
                    </div>
                    
                    <div className="space-y-1 text-sm">
                      <div><strong>Source IP:</strong> {callback.source_ip}</div>
                      <div><strong>URL:</strong> {callback.url}</div>
                      {callback.body && (
                        <div>
                          <strong>Body:</strong>
                          <div className="font-mono text-xs bg-gray-50 p-2 rounded mt-1 break-all">
                            {callback.body}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                
                {callbacks.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    No callbacks received yet. Generated payloads will appear here when they trigger callbacks.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
