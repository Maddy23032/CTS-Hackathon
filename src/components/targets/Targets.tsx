import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  Target, 
  Plus, 
  Trash2, 
  Edit, 
  Globe, 
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react';
import { apiService } from '@/lib/api';

interface ScanTarget {
  id: string;
  name: string;
  url: string;
  description?: string;
  created_at: string;
  last_scanned?: string;
  scan_count: number;
  vulnerabilities_count: number;
  status: 'active' | 'inactive' | 'error';
}

export function Targets() {
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newTarget, setNewTarget] = useState({
    name: '',
    url: '',
    description: ''
  });

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    try {
      setLoading(true);
      // Get recent targets from scan history
      const scanHistory = await apiService.getScanHistory();
      
      // Group by target URL and create target entries
      const targetMap = new Map<string, ScanTarget>();
      
      scanHistory.forEach((scan: any) => {
        const url = scan.target_url;
        if (targetMap.has(url)) {
          const target = targetMap.get(url)!;
          target.scan_count++;
          target.vulnerabilities_count += scan.vulnerabilities_found || 0;
          if (scan.created_at > target.last_scanned!) {
            target.last_scanned = scan.created_at;
          }
        } else {
          targetMap.set(url, {
            id: `target-${Date.now()}-${Math.random()}`,
            name: extractDomainName(url),
            url: url,
            description: `Target discovered from scan history`,
            created_at: scan.created_at,
            last_scanned: scan.created_at,
            scan_count: 1,
            vulnerabilities_count: scan.vulnerabilities_found || 0,
            status: scan.status === 'completed' ? 'active' : 
                   scan.status === 'failed' ? 'error' : 'inactive'
          });
        }
      });
      
      setTargets(Array.from(targetMap.values()));
    } catch (error) {
      console.error('Failed to load targets:', error);
    } finally {
      setLoading(false);
    }
  };

  const extractDomainName = (url: string): string => {
    try {
      const domain = new URL(url).hostname;
      return domain.replace('www.', '');
    } catch {
      return url;
    }
  };

  const handleAddTarget = () => {
    if (!newTarget.name || !newTarget.url) return;
    
    const target: ScanTarget = {
      id: `target-${Date.now()}`,
      name: newTarget.name,
      url: newTarget.url,
      description: newTarget.description,
      created_at: new Date().toISOString(),
      scan_count: 0,
      vulnerabilities_count: 0,
      status: 'inactive'
    };
    
    setTargets(prev => [target, ...prev]);
    setNewTarget({ name: '', url: '', description: '' });
    setShowAddDialog(false);
  };

  const handleDeleteTarget = (id: string) => {
    setTargets(prev => prev.filter(t => t.id !== id));
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'error':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'error':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Targets</h1>
          <p className="text-muted-foreground">Manage and monitor your scan targets</p>
        </div>
        
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Target
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New Target</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target-name">Target Name</Label>
                <Input
                  id="target-name"
                  placeholder="My Application"
                  value={newTarget.name}
                  onChange={(e) => setNewTarget(prev => ({ ...prev, name: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="target-url">Target URL</Label>
                <Input
                  id="target-url"
                  placeholder="https://example.com"
                  value={newTarget.url}
                  onChange={(e) => setNewTarget(prev => ({ ...prev, url: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="target-description">Description (Optional)</Label>
                <Input
                  id="target-description"
                  placeholder="Production environment"
                  value={newTarget.description}
                  onChange={(e) => setNewTarget(prev => ({ ...prev, description: e.target.value }))}
                />
              </div>
              <div className="flex justify-end space-x-2">
                <Button variant="outline" onClick={() => setShowAddDialog(false)}>
                  Cancel
                </Button>
                <Button onClick={handleAddTarget}>
                  Add Target
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Tabs defaultValue="all" className="space-y-4">
        <TabsList>
          <TabsTrigger value="all">All Targets</TabsTrigger>
          <TabsTrigger value="active">Active</TabsTrigger>
          <TabsTrigger value="inactive">Inactive</TabsTrigger>
          <TabsTrigger value="error">Errors</TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="space-y-4">
          {loading ? (
            <div className="text-center py-8">
              <p className="text-muted-foreground">Loading targets...</p>
            </div>
          ) : targets.length === 0 ? (
            <Card>
              <CardContent className="text-center py-8">
                <Target className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No targets found</h3>
                <p className="text-muted-foreground mb-4">
                  Add your first target to start managing your scan infrastructure
                </p>
                <Button onClick={() => setShowAddDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Target
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {targets.map((target) => (
                <Card key={target.id} className="hover:shadow-md transition-shadow">
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center space-x-2">
                        <Globe className="h-5 w-5 text-primary" />
                        <CardTitle className="text-lg">{target.name}</CardTitle>
                      </div>
                      <div className="flex items-center space-x-1">
                        {getStatusIcon(target.status)}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDeleteTarget(target.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <p className="text-sm font-mono text-muted-foreground break-all">
                        {target.url}
                      </p>
                      {target.description && (
                        <p className="text-sm text-muted-foreground mt-1">
                          {target.description}
                        </p>
                      )}
                    </div>
                    
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center space-x-4">
                        <div className="text-center">
                          <p className="font-semibold">{target.scan_count}</p>
                          <p className="text-xs text-muted-foreground">Scans</p>
                        </div>
                        <div className="text-center">
                          <p className="font-semibold">{target.vulnerabilities_count}</p>
                          <p className="text-xs text-muted-foreground">Vulns</p>
                        </div>
                      </div>
                      
                      <Badge className={getStatusColor(target.status)}>
                        {target.status}
                      </Badge>
                    </div>
                    
                    {target.last_scanned && (
                      <div className="flex items-center text-xs text-muted-foreground">
                        <Clock className="h-3 w-3 mr-1" />
                        Last scan: {new Date(target.last_scanned).toLocaleDateString()}
                      </div>
                    )}
                    
                    <div className="flex space-x-2 pt-2">
                      <Button size="sm" className="flex-1">
                        Scan Now
                      </Button>
                      <Button variant="outline" size="sm">
                        <Edit className="h-4 w-4" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="active">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {targets.filter(t => t.status === 'active').map((target) => (
              <Card key={target.id} className="hover:shadow-md transition-shadow">
                {/* Same card content as above */}
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="inactive">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {targets.filter(t => t.status === 'inactive').map((target) => (
              <Card key={target.id} className="hover:shadow-md transition-shadow">
                {/* Same card content as above */}
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="error">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {targets.filter(t => t.status === 'error').map((target) => (
              <Card key={target.id} className="hover:shadow-md transition-shadow">
                {/* Same card content as above */}
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
