import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiService, Vulnerability } from '@/lib/api';
import { 
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { 
  FileText, 
  Download,
  Eye,
  Search,
  Calendar,
  Target,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';

interface ScanReport {
  id: string;
  scan_id?: string; // real scan id from backend (used for downloads)
  timestamp: string;
  target_url: string;
  scan_types: string[];
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  duration: string;
  status: 'completed' | 'running' | 'failed';
}

const Reports: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [downloadingReport, setDownloadingReport] = useState<string | null>(null);

  // Download report function
  const downloadReport = async (scanId: string, format: 'html' | 'pdf' = 'html') => {
    try {
      setDownloadingReport(scanId);
      const blob = await apiService.downloadReport(scanId, format);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `scan_report_${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Failed to download report:', error);
      alert('Failed to download report. Please try again.');
    } finally {
      setDownloadingReport(null);
    }
  };

  // Download all reports
  const downloadAllReports = async () => {
    try {
      setDownloadingReport('all');
      // Generate a comprehensive report with all vulnerabilities
      const allVulnsBlob = await fetch('/api/vulnerabilities').then(res => res.json()).then(data => {
        const htmlContent = generateAllVulnerabilitiesReport(data.vulnerabilities);
        return new Blob([htmlContent], { type: 'text/html' });
      });
      
      const url = window.URL.createObjectURL(allVulnsBlob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `all_vulnerabilities_report_${new Date().toISOString().split('T')[0]}.html`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Failed to download all reports:', error);
      alert('Failed to download reports. Please try again.');
    } finally {
      setDownloadingReport(null);
    }
  };

  // Generate HTML report for all vulnerabilities
  const generateAllVulnerabilitiesReport = (allVulns: Vulnerability[]) => {
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let aiEnrichedCount = 0;
    
    allVulns.forEach(vuln => {
      const severity = (vuln.severity || 'medium').toLowerCase();
      if (severity in severityCounts) {
        (severityCounts as any)[severity]++;
      }
      if (vuln.ai_summary || (vuln.remediation && vuln.remediation.length > 50)) {
        aiEnrichedCount++;
      }
    });

    const vulnDetails = allVulns.map((vuln, i) => {
      const aiBadge = (vuln.ai_summary || (vuln.remediation && vuln.remediation.length > 50)) 
        ? '<span class="ai-badge">🤖 AI Enhanced</span>' : '';
      
      return `
        <div class="vulnerability-item severity-${(vuln.severity || 'medium').toLowerCase()}">
          <h4>#${i + 1}. ${(vuln.type || 'Unknown').toUpperCase()} Vulnerability ${aiBadge}</h4>
          <div class="vuln-meta">
            <span class="severity severity-${(vuln.severity || 'medium').toLowerCase()}">${(vuln.severity || 'Medium').toUpperCase()}</span>
            <span class="url">${vuln.url || 'N/A'}</span>
            ${vuln.parameter ? `<span class='parameter'>Parameter: ${vuln.parameter}</span>` : ''}
          </div>
          <div class="evidence">
            <strong>Evidence:</strong> ${(vuln.evidence || 'No evidence provided').substring(0, 500)}${(vuln.evidence || '').length > 500 ? '...' : ''}
          </div>
          ${vuln.payload ? `<div class='payload'><strong>Payload:</strong> <code>${vuln.payload}</code></div>` : ''}
          ${vuln.remediation ? `<div class='ai-analysis'><strong>🤖 AI Remediation:</strong> ${vuln.remediation}</div>` : ''}
        </div>
      `;
    }).join('');

    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Complete Security Report - All Vulnerabilities</title>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
          .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { text-align: center; margin-bottom: 40px; border-bottom: 3px solid #4f46e5; padding-bottom: 20px; }
          .header h1 { color: #4f46e5; margin: 0; font-size: 2.5rem; }
          .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
          .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
          .summary-card h3 { margin: 0 0 10px 0; font-size: 1.2rem; }
          .summary-card .number { font-size: 2rem; font-weight: bold; }
          .severity-critical { background: linear-gradient(135deg, #dc2626, #ef4444) !important; }
          .severity-high { background: linear-gradient(135deg, #ea580c, #f97316) !important; }
          .severity-medium { background: linear-gradient(135deg, #ca8a04, #eab308) !important; }
          .severity-low { background: linear-gradient(135deg, #16a34a, #22c55e) !important; }
          .vulnerability-item { margin: 20px 0; padding: 20px; border-left: 5px solid #ccc; background: #f9f9f9; border-radius: 5px; }
          .vulnerability-item.severity-critical { border-left-color: #dc2626; background: #fef2f2; }
          .vulnerability-item.severity-high { border-left-color: #ea580c; background: #fff7ed; }
          .vulnerability-item.severity-medium { border-left-color: #ca8a04; background: #fffbeb; }
          .vulnerability-item.severity-low { border-left-color: #16a34a; background: #f0fdf4; }
          .severity { padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8rem; }
          .severity.severity-critical { background: #dc2626; }
          .severity.severity-high { background: #ea580c; }
          .severity.severity-medium { background: #ca8a04; }
          .severity.severity-low { background: #16a34a; }
          .ai-badge { background: linear-gradient(135deg, #8b5cf6, #a855f7); color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; margin-left: 10px; }
          .ai-analysis { background: #f3f4f6; padding: 15px; border-radius: 8px; margin-top: 10px; border-left: 4px solid #8b5cf6; }
          .vuln-meta { margin: 10px 0; }
          .vuln-meta span { margin-right: 15px; display: inline-block; }
          .url { color: #4f46e5; }
          .parameter { background: #e5e7eb; padding: 2px 6px; border-radius: 3px; }
          .evidence { margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }
          .payload code { background: #1f2937; color: #f9fafb; padding: 5px 8px; border-radius: 4px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛡️ Complete Security Report</h1>
            <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
            <p>All vulnerabilities from security scans</p>
          </div>
          
          <div class="summary">
            <div class="summary-card">
              <h3>Total Vulnerabilities</h3>
              <div class="number">${allVulns.length}</div>
            </div>
            <div class="summary-card severity-critical">
              <h3>Critical</h3>
              <div class="number">${severityCounts.critical}</div>
            </div>
            <div class="summary-card severity-high">
              <h3>High</h3>
              <div class="number">${severityCounts.high}</div>
            </div>
            <div class="summary-card severity-medium">
              <h3>Medium</h3>
              <div class="number">${severityCounts.medium}</div>
            </div>
            <div class="summary-card severity-low">
              <h3>Low</h3>
              <div class="number">${severityCounts.low}</div>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #8b5cf6, #a855f7);">
              <h3>🤖 AI Enhanced</h3>
              <div class="number">${aiEnrichedCount}</div>
            </div>
          </div>
          
          <h2>🔍 All Vulnerability Details</h2>
          ${vulnDetails || '<p>No vulnerabilities found.</p>'}
          
          <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #666;">
            <p>Generated by VulnScan Security Scanner | Report includes AI-enhanced vulnerability analysis</p>
          </div>
        </div>
      </body>
      </html>
    `;
  };

  // Fetch vulnerabilities and group them into scan reports
  const fetchReports = async () => {
    try {
      setLoading(true);
  const response = await apiService.getVulnerabilitiesWithFallback();
      
      if (response.vulnerabilities) {
        setVulnerabilities(response.vulnerabilities);
      }
    } catch (error) {
      console.error('Failed to fetch reports:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  // Group vulnerabilities by scan session (simplified - by date for now)
  const groupedReports: ScanReport[] = React.useMemo(() => {
    if (!vulnerabilities.length) return [];

    // Group by real scan_id when available; fallback to date+target composite
    const groups = vulnerabilities.reduce((acc, vuln) => {
      const ts = vuln.timestamp || new Date().toISOString();
      const date = (() => {
        try {
          const d = new Date(ts);
          if (isNaN(d.getTime())) return ts.split('T')[0] || ts;
          return d.toISOString().split('T')[0];
        } catch {
          return (ts.split('T')[0] || ts).toString();
        }
      })();
      const key = (vuln as any).scan_id || `${date}-${vuln.url || 'unknown'}`;
      
      if (!acc[key]) {
        acc[key] = {
          id: key,
          scan_id: (vuln as any).scan_id,
          timestamp: ts,
          target_url: vuln.url || 'unknown',
          scan_types: [
            'XSS', 'SQLi', 'CSRF',
            'Broken Access Control',
            'Cryptographic Failures',
            'Authentication Failures',
            'Integrity Failures',
            'Logging & Monitoring Failures',
            'Security Misconfiguration',
            'Vulnerable Components',
            'SSRF'
          ], // Extended scan types
          vulnerabilities: [],
          total_vulnerabilities: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          duration: '2-5 minutes',
          status: 'completed' as const
        };
      }
      
      acc[key].vulnerabilities.push(vuln);
      acc[key].total_vulnerabilities++;
      
      // Count by severity
      switch (vuln.severity.toLowerCase()) {
        case 'critical': acc[key].critical++; break;
        case 'high': acc[key].high++; break;
        case 'medium': acc[key].medium++; break;
        case 'low': acc[key].low++; break;
      }
      
      return acc;
    }, {} as Record<string, any>);

    return Object.values(groups) as ScanReport[];
  }, [vulnerabilities]);

  // Filter reports based on search term
  const filteredReports = groupedReports.filter(report =>
    report.target_url.toLowerCase().includes(searchTerm.toLowerCase()) ||
    report.scan_types.some(type => type.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-severity-critical text-destructive-foreground';
      case 'high': return 'bg-severity-high text-foreground';
      case 'medium': return 'bg-severity-medium text-foreground';
      case 'low': return 'bg-severity-low text-foreground';
      default: return 'bg-severity-info text-foreground';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed': return 'bg-status-success text-foreground';
      case 'running': return 'bg-status-scanning text-foreground';
      case 'failed': return 'bg-severity-critical text-destructive-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const formatDate = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch {
      return timestamp;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-primary rounded-lg shadow-glow-primary">
            <FileText className="h-6 w-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Scan Reports</h1>
            <p className="text-muted-foreground">View and manage completed security scans</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchReports} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="outline" onClick={downloadAllReports} disabled={downloadingReport === 'all'}>
            <Download className={`h-4 w-4 mr-2 ${downloadingReport === 'all' ? 'animate-spin' : ''}`} />
            {downloadingReport === 'all' ? 'Generating...' : 'Export All'}
          </Button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Reports</p>
                <p className="text-2xl font-bold text-foreground">{loading ? '...' : filteredReports.length}</p>
              </div>
              <FileText className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Vulnerabilities</p>
                <p className="text-2xl font-bold text-foreground">
                  {loading ? '...' : filteredReports.reduce((sum, report) => sum + report.total_vulnerabilities, 0)}
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-severity-high" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div>
              <p className="text-sm text-muted-foreground">Critical Findings</p>
              <p className="text-2xl font-bold text-severity-critical">
                {loading ? '...' : filteredReports.reduce((sum, report) => sum + report.critical, 0)}
              </p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div>
              <p className="text-sm text-muted-foreground">Last Scan</p>
              <p className="text-sm font-bold text-foreground">
                {loading ? '...' : filteredReports.length > 0 ? formatDate(filteredReports[0].timestamp) : 'No scans'}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <Card className="bg-gradient-security border-border">
        <CardContent className="p-4">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search reports by target URL or scan type..."
                  className="pl-10 bg-input border-border"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Reports Table */}
      <Card className="bg-gradient-security border-border">
        <CardHeader>
          <CardTitle className="text-lg text-foreground">
            Completed Scans {loading && <span className="text-sm text-muted-foreground">(Loading...)</span>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {filteredReports.length === 0 && !loading ? (
            <div className="text-center py-8">
              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg text-foreground">No scan reports found</p>
              <p className="text-muted-foreground">Run a security scan to generate reports</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-secondary/20">
                  <TableHead className="text-muted-foreground">Date</TableHead>
                  <TableHead className="text-muted-foreground">Target</TableHead>
                  <TableHead className="text-muted-foreground">Scan Types</TableHead>
                  <TableHead className="text-muted-foreground">Vulnerabilities</TableHead>
                  <TableHead className="text-muted-foreground">Severity Breakdown</TableHead>
                  <TableHead className="text-muted-foreground">Status</TableHead>
                  <TableHead className="text-muted-foreground">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredReports.map((report) => (
                  <TableRow key={report.id} className="border-border hover:bg-secondary/20">
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Calendar className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm text-foreground">{formatDate(report.timestamp)}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Target className="h-4 w-4 text-muted-foreground" />
                        <span className="font-mono text-foreground max-w-xs truncate" title={report.target_url}>
                          {report.target_url}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {report.scan_types.map((type) => (
                          <Badge key={type} variant="outline" className="text-xs">
                            {type}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-lg font-semibold text-foreground">
                        {report.total_vulnerabilities}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {report.critical > 0 && (
                          <Badge className="bg-severity-critical text-destructive-foreground text-xs">
                            C: {report.critical}
                          </Badge>
                        )}
                        {report.high > 0 && (
                          <Badge className="bg-severity-high text-foreground text-xs">
                            H: {report.high}
                          </Badge>
                        )}
                        {report.medium > 0 && (
                          <Badge className="bg-severity-medium text-foreground text-xs">
                            M: {report.medium}
                          </Badge>
                        )}
                        {report.low > 0 && (
                          <Badge className="bg-severity-low text-foreground text-xs">
                            L: {report.low}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge className={getStatusColor(report.status)}>
                        {report.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button variant="ghost" size="sm" title="View Details">
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          title="Download HTML Report"
                            onClick={() => report.scan_id && downloadReport(report.scan_id, 'html')}
                            disabled={downloadingReport === report.id || !report.scan_id}
                        >
                          <Download className={`h-4 w-4 ${downloadingReport === report.id ? 'animate-spin' : ''}`} />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          title="Download PDF Report"
                            onClick={() => report.scan_id && downloadReport(report.scan_id, 'pdf')}
                            disabled={downloadingReport === report.id || !report.scan_id}
                        >
                          <FileText className={`h-4 w-4 ${downloadingReport === report.id ? 'animate-spin' : ''}`} />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Reports;
