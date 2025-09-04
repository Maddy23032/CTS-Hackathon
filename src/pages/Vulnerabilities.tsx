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
  AlertTriangle, 
  Search, 
  Filter,
  Download,
  Eye,
  Shield,
  Zap,
  RefreshCw
} from 'lucide-react';

const Vulnerabilities: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  // Fetch vulnerabilities from API
  const fetchVulnerabilities = async () => {
    try {
      setLoading(true);
      const response = await apiService.getVulnerabilities();
      
      if (response.vulnerabilities) {
        setVulnerabilities(response.vulnerabilities);
        
        // Calculate stats
        const total = response.total || response.vulnerabilities.length;
        const critical = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'critical').length;
        const high = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length;
        const medium = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium').length;
        const low = response.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low').length;
        
        setStats({ total, critical, high, medium, low });
      }
    } catch (error) {
      console.error('Failed to fetch vulnerabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  // Load vulnerabilities on component mount
  useEffect(() => {
    fetchVulnerabilities();
  }, []);

  // Filter vulnerabilities based on search term
  const filteredVulnerabilities = vulnerabilities.filter(vuln =>
    vuln.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    vuln.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
    vuln.parameter.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Format timestamp to relative time
  const getRelativeTime = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffMins < 60) return `${diffMins} minutes ago`;
      if (diffHours < 24) return `${diffHours} hours ago`;
      return `${diffDays} days ago`;
    } catch {
      return timestamp;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-severity-critical text-destructive-foreground';
      case 'high': return 'bg-severity-high text-foreground';
      case 'medium': return 'bg-severity-medium text-foreground';
      case 'low': return 'bg-severity-low text-foreground';
      default: return 'bg-severity-info text-foreground';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-primary rounded-lg shadow-glow-primary">
            <AlertTriangle className="h-6 w-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Vulnerabilities</h1>
            <p className="text-muted-foreground">Manage and analyze security findings</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchVulnerabilities} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Button variant="scanner">
            <Shield className="h-4 w-4 mr-2" />
            New Scan
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Found</p>
                <p className="text-2xl font-bold text-foreground">{loading ? '...' : stats.total}</p>
              </div>
              <Zap className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical</p>
                <p className="text-2xl font-bold text-severity-critical">{loading ? '...' : stats.critical}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-severity-critical" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div>
              <p className="text-sm text-muted-foreground">High</p>
              <p className="text-2xl font-bold text-severity-high">{loading ? '...' : stats.high}</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div>
              <p className="text-sm text-muted-foreground">Medium</p>
              <p className="text-2xl font-bold text-severity-medium">{loading ? '...' : stats.medium}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card className="bg-gradient-security border-border">
        <CardContent className="p-4">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search vulnerabilities..."
                  className="pl-10 bg-input border-border"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card className="bg-gradient-security border-border">
        <CardHeader>
          <CardTitle className="text-lg text-foreground">
            Security Findings {loading && <span className="text-sm text-muted-foreground">(Loading...)</span>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {filteredVulnerabilities.length === 0 && !loading ? (
            <div className="text-center py-8">
              <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg text-foreground">No vulnerabilities found</p>
              <p className="text-muted-foreground">Run a security scan to discover vulnerabilities</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-secondary/20">
                  <TableHead className="text-muted-foreground">Type</TableHead>
                  <TableHead className="text-muted-foreground">Severity</TableHead>
                  <TableHead className="text-muted-foreground">URL</TableHead>
                  <TableHead className="text-muted-foreground">Parameter</TableHead>
                  <TableHead className="text-muted-foreground">CVSS</TableHead>
                  <TableHead className="text-muted-foreground">Confidence</TableHead>
                  <TableHead className="text-muted-foreground">Found</TableHead>
                  <TableHead className="text-muted-foreground">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredVulnerabilities.map((vuln) => (
                  <TableRow key={vuln.id} className="border-border hover:bg-secondary/20">
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {vuln.type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={getSeverityColor(vuln.severity)}>
                        {vuln.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-foreground max-w-xs truncate" title={vuln.url}>
                      {vuln.url}
                    </TableCell>
                    <TableCell className="font-mono text-muted-foreground">{vuln.parameter}</TableCell>
                    <TableCell>
                      <span className="text-sm text-foreground">{vuln.cvss}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {vuln.confidence}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{getRelativeTime(vuln.timestamp)}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm" title="View Details">
                        <Eye className="h-4 w-4" />
                      </Button>
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

export default Vulnerabilities;