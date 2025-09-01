import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  AlertTriangle, 
  Shield, 
  Target, 
  Brain,
  Activity,
  Clock,
  TrendingUp,
  Zap
} from 'lucide-react';

export function DashboardOverview() {
  const stats = {
    totalScans: 127,
    activeScans: 2,
    vulnerabilitiesFound: 43,
    criticalVulns: 5,
    aiAnalysisComplete: 89,
    scanProgress: 67
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-muted-foreground">Monitor your security scanning operations</p>
        </div>
        <Badge className="bg-gradient-primary text-primary-foreground px-4 py-2">
          VulnPy Scanner v2.0
        </Badge>
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
            <div className="text-2xl font-bold text-foreground">{stats.totalScans}</div>
            <p className="text-xs text-status-success">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              +12% from last month
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-security border-border hover:shadow-glow-primary transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Active Scans
            </CardTitle>
            <Activity className="h-4 w-4 text-status-scanning animate-pulse-glow" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{stats.activeScans}</div>
            <p className="text-xs text-status-scanning">
              <Zap className="inline h-3 w-3 mr-1" />
              Currently running
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
            <div className="text-2xl font-bold text-foreground">{stats.vulnerabilitiesFound}</div>
            <p className="text-xs text-severity-critical">
              {stats.criticalVulns} critical findings
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-ai border-border hover:shadow-glow-ai transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              AI Analysis
            </CardTitle>
            <Brain className="h-4 w-4 text-ai-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{stats.aiAnalysisComplete}%</div>
            <p className="text-xs text-ai-primary">
              Enhanced with Groq AI
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Current Scan Progress */}
      <Card className="bg-gradient-security border-border">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg text-foreground">Current Scan Progress</CardTitle>
              <p className="text-sm text-muted-foreground">Target: https://example.com</p>
            </div>
            <Badge className="bg-status-scanning text-foreground animate-pulse-glow">
              <Activity className="h-3 w-3 mr-1" />
              Scanning
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Overall Progress</span>
              <span className="text-foreground font-medium">{stats.scanProgress}%</span>
            </div>
            <Progress value={stats.scanProgress} className="h-2" />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-status-success rounded-full"></div>
              <span className="text-sm text-muted-foreground">Crawling Complete</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-status-scanning rounded-full animate-pulse"></div>
              <span className="text-sm text-muted-foreground">Vulnerability Testing</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-muted rounded-full"></div>
              <span className="text-sm text-muted-foreground">AI Analysis Pending</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recent Activity Feed */}
      <Card className="bg-gradient-security border-border">
        <CardHeader>
          <CardTitle className="text-lg text-foreground flex items-center gap-2">
            <Clock className="h-5 w-5 text-primary" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { time: '10:34 AM', message: 'XSS vulnerability detected in /login form', severity: 'high' },
              { time: '10:32 AM', message: 'SQL injection test completed for /api/users', severity: 'medium' },
              { time: '10:30 AM', message: 'Started scanning target https://example.com', severity: 'info' },
              { time: '10:28 AM', message: 'AI analysis completed for previous scan', severity: 'success' },
              { time: '10:25 AM', message: 'CSRF token validation bypassed in /admin', severity: 'critical' }
            ].map((activity, index) => (
              <div key={index} className="flex items-start gap-3 p-3 rounded-lg bg-card border border-border hover:bg-secondary/20 transition-colors">
                <div className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${
                  activity.severity === 'critical' ? 'bg-severity-critical' :
                  activity.severity === 'high' ? 'bg-severity-high' :
                  activity.severity === 'medium' ? 'bg-severity-medium' :
                  activity.severity === 'success' ? 'bg-status-success' :
                  'bg-severity-info'
                }`}></div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground">{activity.message}</p>
                  <p className="text-xs text-muted-foreground">{activity.time}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}