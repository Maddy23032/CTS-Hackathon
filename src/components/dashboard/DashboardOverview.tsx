import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { apiService } from '@/lib/api';
import { useScan } from '@/hooks/useScan';
import { 
  AlertTriangle, 
  Shield, 
  Target, 
  Brain,
  Activity,
  Clock,
  TrendingUp,
  Zap,
  RefreshCw
} from 'lucide-react';

export function DashboardOverview() {
  const { scanStatus } = useScan();
  const [vulnerabilityStats, setVulnerabilityStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    byType: {} as Record<string, number>
  });
  const [loading, setLoading] = useState(true);

  // Fetch vulnerability statistics
  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await apiService.getVulnerabilities();
      
      if (response.vulnerabilities) {
        const total = response.total || response.vulnerabilities.length;
        const critical = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'critical').length;
        const high = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length;
        const medium = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium').length;
        const low = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low').length;
        const byType = response.by_type || {};
        
        setVulnerabilityStats({ total, critical, high, medium, low, byType });
      }
    } catch (error) {
      console.error('Failed to fetch vulnerability stats:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, [scanStatus.scan_id]); // Refresh when a new scan starts

  const stats = {
    totalScans: 1, // We can track this later
    activeScans: scanStatus.is_scanning ? 1 : 0,
    vulnerabilitiesFound: vulnerabilityStats.total,
    criticalVulns: vulnerabilityStats.critical,
    aiAnalysisComplete: scanStatus.stats?.ai_calls_made || 0,
    scanProgress: scanStatus.progress
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-muted-foreground">Monitor your security scanning operations</p>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={fetchStats} 
            disabled={loading}
            className="p-2 hover:bg-secondary rounded-lg transition-colors"
            title="Refresh data"
          >
            <RefreshCw className={`h-4 w-4 text-muted-foreground ${loading ? 'animate-spin' : ''}`} />
          </button>
          <Badge className="bg-gradient-primary text-primary-foreground px-4 py-2">
            VulnPy Scanner v2.0
          </Badge>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-gradient-security border-border hover:shadow-glow-primary transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Scans
            </CardTitle>
            <Target className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{loading ? '...' : stats.totalScans}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              System operational
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-security border-border hover:shadow-glow-primary transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Active Scans
            </CardTitle>
            <Activity className={`h-4 w-4 ${scanStatus.is_scanning ? 'text-status-scanning animate-pulse-glow' : 'text-muted-foreground'}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{stats.activeScans}</div>
            <p className="text-xs text-status-scanning">
              <Zap className="inline h-3 w-3 mr-1" />
              {scanStatus.is_scanning ? 'Currently running' : 'Idle'}
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-security border-border hover:shadow-glow-critical transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Vulnerabilities
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-severity-high" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{loading ? '...' : stats.vulnerabilitiesFound}</div>
            <p className="text-xs text-severity-critical">
              {loading ? 'Loading...' : `${stats.criticalVulns} critical findings`}
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-ai border-border hover:shadow-glow-ai transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              AI Calls Made
            </CardTitle>
            <Brain className="h-4 w-4 text-ai-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{stats.aiAnalysisComplete}</div>
            <p className="text-xs text-ai-primary">
              Enhanced with Groq AI
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Current Scan Progress */}
      {scanStatus.is_scanning && (
        <Card className="bg-gradient-security border-border">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-lg text-foreground">Current Scan Progress</CardTitle>
                <p className="text-sm text-muted-foreground">Scan ID: {scanStatus.scan_id}</p>
              </div>
              <Badge className="bg-status-scanning text-foreground animate-pulse-glow">
                <Activity className="h-3 w-3 mr-1" />
                {scanStatus.phase || 'Scanning'}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Overall Progress</span>
                <span className="text-foreground font-medium">{scanStatus.progress}%</span>
              </div>
              <Progress value={scanStatus.progress} className="h-2" />
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
              <div className="space-y-1">
                <div className="text-sm text-muted-foreground">URLs Crawled</div>
                <div className="text-lg font-semibold text-foreground">{scanStatus.stats?.urls_crawled || 0}</div>
              </div>
              <div className="space-y-1">
                <div className="text-sm text-muted-foreground">Forms Found</div>
                <div className="text-lg font-semibold text-foreground">{scanStatus.stats?.forms_found || 0}</div>
              </div>
              <div className="space-y-1">
                <div className="text-sm text-muted-foreground">Vulnerabilities Found</div>
                <div className="text-lg font-semibold text-severity-high">{scanStatus.stats?.vulnerabilities_found || 0}</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent Vulnerabilities or Activity Feed */}
      <Card className="bg-gradient-security border-border">
        <CardHeader>
          <CardTitle className="text-lg text-foreground flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-primary" />
            Recent Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8">
              <RefreshCw className="h-8 w-8 text-muted-foreground mx-auto mb-2 animate-spin" />
              <p className="text-muted-foreground">Loading vulnerabilities...</p>
            </div>
          ) : vulnerabilityStats.total === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg text-foreground">No vulnerabilities found</p>
              <p className="text-muted-foreground">Run a security scan to discover vulnerabilities</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="text-center p-3 rounded-lg bg-card border border-border">
                  <div className="text-2xl font-bold text-severity-critical">{vulnerabilityStats.critical}</div>
                  <div className="text-sm text-muted-foreground">Critical</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-card border border-border">
                  <div className="text-2xl font-bold text-severity-high">{vulnerabilityStats.high}</div>
                  <div className="text-sm text-muted-foreground">High</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-card border border-border">
                  <div className="text-2xl font-bold text-severity-medium">{vulnerabilityStats.medium}</div>
                  <div className="text-sm text-muted-foreground">Medium</div>
                </div>
              </div>
              
              {/* Vulnerability Type Breakdown */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">Vulnerability Types Found:</p>
                {Object.entries(vulnerabilityStats.byType).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between p-2 rounded bg-card border border-border">
                    <span className="text-sm text-foreground capitalize">{type}</span>
                    <Badge variant="outline">{count}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}