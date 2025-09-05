import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { 
  Brain, 
  Zap, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp,
  Shield,
  Target,
  Activity,
  Lightbulb
} from 'lucide-react';
import { apiService } from '@/lib/api';

interface AIEnrichedVulnerability {
  id: string;
  type: string;
  url: string;
  parameter: string;
  payload: string;
  evidence: string;
  remediation: string;
  cvss: number;
  severity: string;
  ai_summary?: string;
  confidence: string;
  timestamp: string;
}

interface AIAnalysisStats {
  total_vulnerabilities: number;
  ai_enriched: number;
  high_confidence: number;
  recommendations_generated: number;
  analysis_coverage: number;
}

export function AIAnalysis() {
  const [vulnerabilities, setVulnerabilities] = useState<AIEnrichedVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<AIAnalysisStats>({
    total_vulnerabilities: 0,
    ai_enriched: 0,
    high_confidence: 0,
    recommendations_generated: 0,
    analysis_coverage: 0
  });
  const [selectedVuln, setSelectedVuln] = useState<AIEnrichedVulnerability | null>(null);

  useEffect(() => {
    fetchAIAnalysis();
  }, []);

  const fetchAIAnalysis = async () => {
    try {
      setLoading(true);
  const response = await apiService.getVulnerabilitiesWithFallback();
      const vulns = response.vulnerabilities || [];
      
      setVulnerabilities(vulns);
      
      // Calculate AI analysis statistics
      const aiEnriched = vulns.filter(v => v.ai_summary).length;
      const highConfidence = vulns.filter(v => v.confidence === 'High').length;
      const recommendationsGenerated = vulns.filter(v => v.remediation && v.remediation.length > 50).length;
      const coverage = vulns.length > 0 ? Math.round((aiEnriched / vulns.length) * 100) : 0;
      
      setStats({
        total_vulnerabilities: vulns.length,
        ai_enriched: aiEnriched,
        high_confidence: highConfidence,
        recommendations_generated: recommendationsGenerated,
        analysis_coverage: coverage
      });
    } catch (error) {
      console.error('Failed to fetch AI analysis:', error);
    } finally {
      setLoading(false);
    }
  };

  const triggerAIEnrichment = async () => {
    try {
      setLoading(true);
      await apiService.triggerAIEnrichment();
      // Refresh data after enrichment
      setTimeout(() => {
        fetchAIAnalysis();
      }, 2000);
    } catch (error) {
      console.error('Failed to trigger AI enrichment:', error);
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence.toLowerCase()) {
      case 'high': return 'bg-emerald-100 text-emerald-800';
      case 'medium': return 'bg-blue-100 text-blue-800';
      case 'low': return 'bg-orange-100 text-orange-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading && vulnerabilities.length === 0) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-primary rounded-lg shadow-glow-primary">
            <Brain className="h-6 w-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">AI Analysis</h1>
            <p className="text-muted-foreground">AI-powered vulnerability insights and recommendations</p>
          </div>
        </div>
        
        <div className="flex items-center justify-center py-12">
          <div className="text-center space-y-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
            <p className="text-muted-foreground">Loading AI analysis...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-primary rounded-lg shadow-glow-primary">
            <Brain className="h-6 w-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">AI Analysis</h1>
            <p className="text-muted-foreground">AI-powered vulnerability insights and recommendations</p>
          </div>
        </div>
        
        <Button onClick={triggerAIEnrichment} disabled={loading} className="bg-gradient-primary">
          <Zap className="h-4 w-4 mr-2" />
          {loading ? 'Analyzing...' : 'Trigger AI Analysis'}
        </Button>
      </div>

      {/* AI Analysis Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="bg-gradient-security border-border">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Vulnerabilities</p>
                <p className="text-2xl font-bold text-foreground">{stats.total_vulnerabilities}</p>
              </div>
              <Target className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-security border-border">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">AI Enriched</p>
                <p className="text-2xl font-bold text-foreground">{stats.ai_enriched}</p>
              </div>
              <Brain className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-security border-border">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">High Confidence</p>
                <p className="text-2xl font-bold text-foreground">{stats.high_confidence}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-security border-border">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Analysis Coverage</p>
                <p className="text-2xl font-bold text-foreground">{stats.analysis_coverage}%</p>
              </div>
              <Activity className="h-8 w-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Analysis Coverage Progress */}
      <Card className="bg-gradient-security border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-primary" />
            AI Analysis Coverage
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Coverage Progress</span>
              <span>{stats.analysis_coverage}%</span>
            </div>
            <Progress value={stats.analysis_coverage} className="h-2" />
            <p className="text-xs text-muted-foreground">
              {stats.ai_enriched} of {stats.total_vulnerabilities} vulnerabilities have been analyzed by AI
            </p>
          </div>
        </CardContent>
      </Card>

      {/* AI Analysis Results */}
      <Tabs defaultValue="enriched" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="enriched">AI Enriched ({stats.ai_enriched})</TabsTrigger>
          <TabsTrigger value="all">All Vulnerabilities ({stats.total_vulnerabilities})</TabsTrigger>
          <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
        </TabsList>

        <TabsContent value="enriched" className="space-y-4">
          {vulnerabilities.filter(v => v.ai_summary).length === 0 ? (
            <Card className="bg-gradient-security border-border">
              <CardContent className="p-8 text-center">
                <Brain className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-foreground mb-2">No AI Analysis Available</h3>
                <p className="text-muted-foreground mb-4">
                  Run a scan with AI analysis enabled to see AI-powered insights
                </p>
                <Button onClick={triggerAIEnrichment} disabled={loading}>
                  <Zap className="h-4 w-4 mr-2" />
                  Start AI Analysis
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {vulnerabilities.filter(v => v.ai_summary).map((vuln) => (
                <Card key={vuln.id} className="bg-gradient-security border-border cursor-pointer hover:bg-secondary/20 transition-colors"
                      onClick={() => setSelectedVuln(vuln)}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge className={getSeverityColor(vuln.severity)}>
                          {vuln.severity}
                        </Badge>
                        <Badge variant="outline" className={getConfidenceColor(vuln.confidence)}>
                          {vuln.confidence} Confidence
                        </Badge>
                        <span className="text-sm font-medium">{vuln.type}</span>
                      </div>
                      <Badge variant="secondary" className="bg-blue-100 text-blue-800">
                        <Brain className="h-3 w-3 mr-1" />
                        AI Analyzed
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm text-muted-foreground">URL</p>
                        <p className="font-mono text-sm break-all">{vuln.url}</p>
                      </div>
                      
                      {vuln.ai_summary && (
                        <div>
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <Lightbulb className="h-3 w-3" />
                            AI Summary
                          </p>
                          <p className="text-sm bg-blue-50 dark:bg-blue-950/20 p-3 rounded border border-blue-200 dark:border-blue-800 text-blue-900 dark:text-blue-100">
                            {vuln.ai_summary}
                          </p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="all" className="space-y-4">
          <div className="grid grid-cols-1 gap-4">
            {vulnerabilities.map((vuln) => (
              <Card key={vuln.id} className="bg-gradient-security border-border">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge className={getSeverityColor(vuln.severity)}>
                        {vuln.severity}
                      </Badge>
                      <span className="text-sm font-medium">{vuln.type}</span>
                    </div>
                    {vuln.ai_summary ? (
                      <Badge variant="secondary" className="bg-green-100 text-green-800">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        AI Analyzed
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-muted-foreground">
                        <Clock className="h-3 w-3 mr-1" />
                        Pending Analysis
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">URL</p>
                  <p className="font-mono text-sm break-all">{vuln.url}</p>
                  {vuln.parameter && (
                    <>
                      <p className="text-sm text-muted-foreground mt-2">Parameter</p>
                      <p className="font-mono text-sm">{vuln.parameter}</p>
                    </>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="recommendations" className="space-y-4">
          <Card className="bg-gradient-security border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Security Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {vulnerabilities.filter(v => v.ai_summary).length === 0 ? (
                <p className="text-muted-foreground">No AI-powered recommendations available. Run a scan with AI analysis to get personalized security advice.</p>
              ) : (
                <div className="space-y-4">
                  <div className="bg-amber-50 dark:bg-amber-950/20 p-4 rounded border border-amber-200 dark:border-amber-800">
                    <h4 className="font-medium text-amber-800 dark:text-amber-200 mb-2">High Priority Actions</h4>
                    <ul className="space-y-1 text-sm text-amber-700 dark:text-amber-300">
                      <li>• Address {vulnerabilities.filter(v => v.severity === 'High').length} high-severity vulnerabilities immediately</li>
                      <li>• Implement input validation for detected injection vulnerabilities</li>
                      <li>• Review and strengthen authentication mechanisms</li>
                    </ul>
                  </div>
                  
                  <div className="bg-blue-50 dark:bg-blue-950/20 p-4 rounded border border-blue-200 dark:border-blue-800">
                    <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">Security Best Practices</h4>
                    <ul className="space-y-1 text-sm text-blue-700 dark:text-blue-300">
                      <li>• Enable Content Security Policy (CSP) headers</li>
                      <li>• Implement proper session management</li>
                      <li>• Use HTTPS for all sensitive communications</li>
                      <li>• Regular security testing and code reviews</li>
                    </ul>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Detailed View Modal would go here */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50" onClick={() => setSelectedVuln(null)}>
          <Card className="max-w-2xl w-full max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-primary" />
                Vulnerability Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Badge className={getSeverityColor(selectedVuln.severity)}>
                  {selectedVuln.severity}
                </Badge>
                <Badge variant="outline">{selectedVuln.type}</Badge>
              </div>
              
              <Separator />
              
              <div>
                <h4 className="font-medium mb-2">URL</h4>
                <p className="font-mono text-sm bg-secondary p-2 rounded break-all">{selectedVuln.url}</p>
              </div>
              
              {selectedVuln.ai_summary && (
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-1">
                    <Brain className="h-4 w-4" />
                    AI Analysis
                  </h4>
                  <p className="text-sm bg-blue-50 dark:bg-blue-950/20 p-3 rounded border border-blue-200 dark:border-blue-800 text-blue-900 dark:text-blue-100">
                    {selectedVuln.ai_summary}
                  </p>
                </div>
              )}
              
              <div>
                <h4 className="font-medium mb-2">Evidence</h4>
                <p className="text-sm bg-secondary p-2 rounded">{selectedVuln.evidence}</p>
              </div>
              
              <div>
                <h4 className="font-medium mb-2">Remediation</h4>
                <p className="text-sm bg-secondary p-2 rounded">{selectedVuln.remediation}</p>
              </div>
              
              <div className="flex justify-end">
                <Button variant="outline" onClick={() => setSelectedVuln(null)}>
                  Close
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
