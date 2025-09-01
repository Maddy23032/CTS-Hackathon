import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
  Zap
} from 'lucide-react';

const Vulnerabilities: React.FC = () => {
  const vulnerabilities = [
    {
      id: 1,
      type: 'XSS',
      severity: 'High',
      url: '/login',
      parameter: 'username',
      confidence: 95,
      status: 'Open',
      found: '2 hours ago'
    },
    {
      id: 2,
      type: 'SQL Injection',
      severity: 'Critical',
      url: '/api/users',
      parameter: 'id',
      confidence: 100,
      status: 'Open',
      found: '3 hours ago'
    },
    {
      id: 3,
      type: 'CSRF',
      severity: 'Medium',
      url: '/admin/delete',
      parameter: 'token',
      confidence: 87,
      status: 'Under Review',
      found: '1 day ago'
    },
    {
      id: 4,
      type: 'XSS',
      severity: 'Low',
      url: '/search',
      parameter: 'query',
      confidence: 72,
      status: 'Fixed',
      found: '2 days ago'
    }
  ];

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
      case 'open': return 'bg-severity-critical text-destructive-foreground';
      case 'under review': return 'bg-status-warning text-foreground';
      case 'fixed': return 'bg-status-success text-foreground';
      default: return 'bg-muted text-muted-foreground';
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
                <p className="text-2xl font-bold text-foreground">43</p>
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
                <p className="text-2xl font-bold text-severity-critical">5</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-severity-critical" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div>
              <p className="text-sm text-muted-foreground">High</p>
              <p className="text-2xl font-bold text-severity-high">12</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-4">
            <div>
              <p className="text-sm text-muted-foreground">Fixed</p>
              <p className="text-2xl font-bold text-status-success">18</p>
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
          <CardTitle className="text-lg text-foreground">Security Findings</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-secondary/20">
                <TableHead className="text-muted-foreground">Type</TableHead>
                <TableHead className="text-muted-foreground">Severity</TableHead>
                <TableHead className="text-muted-foreground">URL</TableHead>
                <TableHead className="text-muted-foreground">Parameter</TableHead>
                <TableHead className="text-muted-foreground">Confidence</TableHead>
                <TableHead className="text-muted-foreground">Status</TableHead>
                <TableHead className="text-muted-foreground">Found</TableHead>
                <TableHead className="text-muted-foreground">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulnerabilities.map((vuln) => (
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
                  <TableCell className="font-mono text-foreground">{vuln.url}</TableCell>
                  <TableCell className="font-mono text-muted-foreground">{vuln.parameter}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-muted rounded-full h-2">
                        <div 
                          className="bg-primary h-2 rounded-full" 
                          style={{ width: `${vuln.confidence}%` }}
                        ></div>
                      </div>
                      <span className="text-sm text-foreground">{vuln.confidence}%</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge className={getStatusColor(vuln.status)}>
                      {vuln.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{vuln.found}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm">
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default Vulnerabilities;