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

    // Group by date and target
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
      const key = `${date}-${vuln.url || 'unknown'}`;
      
      if (!acc[key]) {
        acc[key] = {
          id: key,
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
          <Button variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export All
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
                        <Button variant="ghost" size="sm" title="Download Report">
                          <Download className="h-4 w-4" />
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
