import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  BarChart3, 
  TrendingUp, 
  Shield, 
  AlertTriangle,
  Target,
  Calendar,
  Activity,
  PieChart,
  Users,
  Globe,
  Brain,
  Database
} from 'lucide-react';
import { apiService } from '@/lib/api';

interface AnalyticsData {
  total_scans: number;
  total_vulnerabilities: number;
  vulnerability_breakdown: {
    xss: number;
    sqli: number;
    csrf: number;
    lfi: number;
    rfi: number;
  };
  severity_breakdown: {
    high: number;
    medium: number;
    low: number;
  };
  scan_trends: Array<{
    date: string;
    scans: number;
    vulnerabilities: number;
  }>;
  top_targets: Array<{
    url: string;
    scan_count: number;
    vulnerability_count: number;
  }>;
  recent_activity: Array<{
    date: string;
    type: string;
    target: string;
    vulnerabilities_found: number;
  }>;
}

export function Analysis() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(30); // days

  useEffect(() => {
    loadAnalytics();
  }, [timeRange]);

  const loadAnalytics = async () => {
    try {
      setLoading(true);
      
      // Load analytics data from backend
  const analyticsData = await apiService.getAnalytics(timeRange);
  const scanHistory = await apiService.getScanHistory();
  const vulnResp = await apiService.getVulnerabilitiesWithFallback();
  const vulnerabilities = vulnResp.vulnerabilities;
      
      // Process the data for analytics
      const processedData: AnalyticsData = {
  total_scans: Array.isArray((scanHistory as any).scans) ? (scanHistory as any).scans.length : (Array.isArray(scanHistory) ? scanHistory.length : 0),
  total_vulnerabilities: vulnerabilities.length,
        vulnerability_breakdown: {
          xss: vulnerabilities.filter((v: any) => v.type.toLowerCase() === 'xss').length,
          sqli: vulnerabilities.filter((v: any) => v.type.toLowerCase() === 'sqli').length,
          csrf: vulnerabilities.filter((v: any) => v.type.toLowerCase() === 'csrf').length,
          lfi: vulnerabilities.filter((v: any) => v.type.toLowerCase() === 'lfi').length,
          rfi: vulnerabilities.filter((v: any) => v.type.toLowerCase() === 'rfi').length,
        },
        severity_breakdown: {
          high: vulnerabilities.filter((v: any) => v.severity?.toLowerCase() === 'high').length,
          medium: vulnerabilities.filter((v: any) => v.severity?.toLowerCase() === 'medium').length,
          low: vulnerabilities.filter((v: any) => v.severity?.toLowerCase() === 'low').length,
        },
  scan_trends: generateScanTrends(scanHistory.scans || []),
  top_targets: generateTopTargets(scanHistory.scans || []),
  recent_activity: (scanHistory.scans || []).slice(0, 10).map((s: any) => ({
    date: s.created_at || new Date().toISOString(),
    type: s.status || 'scan',
    target: s.target_url || 'unknown',
    vulnerabilities_found: s.vulnerabilities_found || 0,
  }))
      };
      
      setAnalytics(processedData);
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateScanTrends = (scans: any[]) => {
    const trends: { [key: string]: { scans: number; vulnerabilities: number } } = {};
    
    scans.forEach(scan => {
      const date = new Date(scan.created_at).toISOString().split('T')[0];
      if (!trends[date]) {
        trends[date] = { scans: 0, vulnerabilities: 0 };
      }
      trends[date].scans++;
      trends[date].vulnerabilities += scan.vulnerabilities_found || 0;
    });
    
    return Object.entries(trends).map(([date, data]) => ({
      date,
      scans: data.scans,
      vulnerabilities: data.vulnerabilities
    })).slice(-7); // Last 7 days
  };

  const generateTopTargets = (scans: any[]) => {
    const targets: { [key: string]: { scan_count: number; vulnerability_count: number } } = {};
    
    scans.forEach(scan => {
      const url = scan.target_url;
      if (!targets[url]) {
        targets[url] = { scan_count: 0, vulnerability_count: 0 };
      }
      targets[url].scan_count++;
      targets[url].vulnerability_count += scan.vulnerabilities_found || 0;
    });
    
    return Object.entries(targets)
      .map(([url, data]) => ({
        url,
        scan_count: data.scan_count,
        vulnerability_count: data.vulnerability_count
      }))
      .sort((a, b) => b.vulnerability_count - a.vulnerability_count)
      .slice(0, 5);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-green-100 text-green-800 border-green-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getVulnTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'xss':
        return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'sqli':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'csrf':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      default:
        return 'bg-blue-100 text-blue-800 border-blue-200';
    }
  };

  if (loading) {
    return (
      <div className="container mx-auto p-6">
        <div className="text-center py-8">
          <Activity className="h-12 w-12 mx-auto text-muted-foreground mb-4 animate-spin" />
          <p className="text-muted-foreground">Loading analytics...</p>
        </div>
      </div>
    );
  }

  if (!analytics) {
    return (
      <div className="container mx-auto p-6">
        <div className="text-center py-8">
          <BarChart3 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
          <p className="text-muted-foreground">Failed to load analytics data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Analytics</h1>
          <p className="text-muted-foreground">Insights and trends from your vulnerability scans</p>
        </div>
        
        <div className="flex space-x-2">
          <Button
            variant={timeRange === 7 ? "default" : "outline"}
            onClick={() => setTimeRange(7)}
          >
            7 Days
          </Button>
          <Button
            variant={timeRange === 30 ? "default" : "outline"}
            onClick={() => setTimeRange(30)}
          >
            30 Days
          </Button>
          <Button
            variant={timeRange === 90 ? "default" : "outline"}
            onClick={() => setTimeRange(90)}
          >
            90 Days
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics.total_scans}</div>
            <p className="text-xs text-muted-foreground">
              +12% from last period
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities Found</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics.total_vulnerabilities}</div>
            <p className="text-xs text-muted-foreground">
              Across all scans
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Severity</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{analytics.severity_breakdown.high}</div>
            <p className="text-xs text-muted-foreground">
              Critical vulnerabilities
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">94%</div>
            <p className="text-xs text-muted-foreground">
              Successful scans
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="targets">Targets</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Vulnerability Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <PieChart className="h-5 w-5" />
                  Vulnerability Types
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {Object.entries(analytics.vulnerability_breakdown).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Badge className={getVulnTypeColor(type)}>
                        {type.toUpperCase()}
                      </Badge>
                      <span className="text-sm">{count} found</span>
                    </div>
                    <div className="w-24">
                      <Progress 
                        value={(count / analytics.total_vulnerabilities) * 100} 
                        className="h-2"
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Severity Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  Severity Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {Object.entries(analytics.severity_breakdown).map(([severity, count]) => (
                  <div key={severity} className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Badge className={getSeverityColor(severity)}>
                        {severity.charAt(0).toUpperCase() + severity.slice(1)}
                      </Badge>
                      <span className="text-sm">{count} vulnerabilities</span>
                    </div>
                    <div className="w-24">
                      <Progress 
                        value={(count / analytics.total_vulnerabilities) * 100} 
                        className="h-2"
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Recent Activity */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Recent Scan Activity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {analytics.recent_activity.map((activity, index) => (
                  <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-secondary/20">
                    <div className="flex items-center space-x-3">
                      <div className="flex-shrink-0">
                        <Calendar className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div>
                        <p className="text-sm font-medium">{activity.target}</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(activity.date).toLocaleDateString()} - {activity.vulnerabilities_found} vulnerabilities found
                        </p>
                      </div>
                    </div>
                    <Badge variant="outline">
                      {activity.type || 'scan'}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vulnerabilities" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Vulnerability Details</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Detailed vulnerability analysis and trends will be displayed here.
                This section will show vulnerability patterns, affected URLs, and remediation insights.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="targets" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                Top Vulnerable Targets
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {analytics.top_targets.map((target, index) => (
                  <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-secondary/20">
                    <div className="flex items-center space-x-3">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                        <span className="text-xs font-bold">{index + 1}</span>
                      </div>
                      <div>
                        <p className="text-sm font-medium font-mono">{target.url}</p>
                        <p className="text-xs text-muted-foreground">
                          {target.scan_count} scans performed
                        </p>
                      </div>
                    </div>
                    <Badge variant={target.vulnerability_count > 10 ? "destructive" : target.vulnerability_count > 5 ? "secondary" : "default"}>
                      {target.vulnerability_count} vulns
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="trends" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Scan Trends (Last 7 Days)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {analytics.scan_trends.map((trend, index) => (
                  <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-secondary/20">
                    <div className="flex items-center space-x-3">
                      <div className="text-sm font-medium">
                        {new Date(trend.date).toLocaleDateString()}
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-center">
                        <p className="text-sm font-bold">{trend.scans}</p>
                        <p className="text-xs text-muted-foreground">Scans</p>
                      </div>
                      <div className="text-center">
                        <p className="text-sm font-bold">{trend.vulnerabilities}</p>
                        <p className="text-xs text-muted-foreground">Vulns</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
