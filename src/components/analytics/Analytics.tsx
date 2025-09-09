// Analytics.tsx
// Component for displaying analytics and trends

import React, { useState, useEffect, useMemo } from 'react';
import './analytics-tooltip.css';
import { apiService, type AnalyticsResponse } from '../../lib/api';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

export const Analytics: React.FC = () => {
  const [analytics, setAnalytics] = useState<AnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(30);

  const fetchAnalytics = async () => {
    setLoading(true);
    try {
      const data = await apiService.getAnalytics(timeRange);
      console.log('Analytics data received:', data); // Debug log
      setAnalytics(data);
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
      setAnalytics(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, [timeRange]);

  const getLatestDayData = () => {
    if (!analytics?.daily_data || analytics.daily_data.length === 0) return null;
    return analytics.daily_data[analytics.daily_data.length - 1];
  };

  const getTotalVulnerabilities = () => {
    if (!analytics?.daily_data) return 0;
    return analytics.daily_data.reduce((total, day) => {
      return total + Object.values(day.vulnerabilities_found || {}).reduce((sum, count) => sum + count, 0);
    }, 0);
  };

  const vulnByType = useMemo(() => {
    if (!analytics?.daily_data) return [] as Array<{ key: string; name: string; value: number }>;
    const totals: Record<string, number> = {};
    const EXCLUDED = new Set(['lfi', 'rfi']);
    const LABELS: Record<string, string> = {
      xss: 'XSS',
      sqli: 'SQLi',
      csrf: 'CSRF',
      ssrf: 'SSRF',
      security_misconfiguration: 'Security Misconfiguration',
      vulnerable_components: 'Vulnerable Components',
      broken_access_control: 'Broken Access Control',
      cryptographic_failures: 'Cryptographic Failures',
      authentication_failures: 'Authentication Failures',
      integrity_failures: 'Integrity Failures',
      logging_monitoring_failures: 'Logging & Monitoring Failures',
    };
    analytics.daily_data.forEach(day => {
      Object.entries(day.vulnerabilities_found || {}).forEach(([type, count]) => {
        const key = (type || '').toLowerCase();
        if (EXCLUDED.has(key)) return;
        totals[key] = (totals[key] || 0) + (count as number);
      });
    });
    return Object.entries(totals)
      .filter(([_, value]) => value > 0) // Only include types with actual vulnerabilities
      .map(([key, value]) => ({ key, name: LABELS[key] || key, value: Number(value) }))
      .sort((a, b) => b.value - a.value);
  }, [analytics]);

  const COLORS = [
    '#1f77b4','#ff7f0e','#2ca02c','#d62728','#9467bd',
    '#8c564b','#e377c2','#7f7f7f','#bcbd22','#17becf'
  ];

  const getTotalSeverityDistribution = () => {
    if (!analytics?.daily_data) return {};
    const distribution: { [key: string]: number } = {};
    
    analytics.daily_data.forEach(day => {
      Object.entries(day.severity_distribution || {}).forEach(([severity, count]) => {
        distribution[severity] = (distribution[severity] || 0) + count;
      });
    });
    
    return distribution;
  };

  if (loading) {
    return (
      <div className="p-6 max-w-7xl mx-auto">
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-2 text-gray-600">Loading analytics...</p>
        </div>
      </div>
    );
  }

  // Provide a safe fallback so we always show the dashboard (with zeros) instead of the old empty-state screen
  const safeAnalytics: AnalyticsResponse = analytics ?? {
    date_range: '',
    total_scans: 0,
    vulnerability_trends: {},
    scan_success_rate: 0,
    daily_data: []
  };

  // If no data yet, still allow user to change range / update analytics without hiding the layout.
  const hasData = (safeAnalytics.daily_data && safeAnalytics.daily_data.length > 0);

  const latestDay = getLatestDayData();
  const totalVulns = getTotalVulnerabilities();
  const severityDist = getTotalSeverityDistribution();

  return (
    <div className="p-6 max-w-7xl mx-auto text-foreground">
      {/* Header */}
      <div className="mb-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground mb-2">📊 Analytics Dashboard</h1>
          <p className="text-sm text-muted-foreground">Historical scan & vulnerability trends</p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <label className="text-sm font-medium text-muted-foreground">Range:</label>
          {[7, 14, 30, 90].map((days) => (
            <button
              key={days}
              onClick={() => setTimeRange(days)}
              className={`px-3 py-2 rounded text-sm transition-colors ${
                timeRange === days
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              {days}d
            </button>
          ))}
          <span className="mx-2 h-6 w-px bg-gray-300" />
          <button
            onClick={async () => { await apiService.updateAnalytics(); fetchAnalytics(); }}
            className="px-3 py-2 rounded text-sm bg-indigo-500 text-white hover:bg-indigo-600 disabled:opacity-50"
            title="Update today's analytics"
          >Update Today</button>
          <button
            onClick={async () => { if (confirm('Rebuild analytics for last 30 days? This may take a moment.')) { await apiService.rebuildAnalytics(30); fetchAnalytics(); } }}
            className="px-3 py-2 rounded text-sm bg-amber-500 text-white hover:bg-amber-600 disabled:opacity-50"
            title="Recompute last 30 days"
          >Rebuild 30d</button>
        </div>
      </div>

  {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">🔍</div>
            <div>
  <p className="text-muted-foreground text-sm">Total Scans</p>
  <p className="text-2xl font-bold text-foreground">{safeAnalytics.total_scans}</p>
            </div>
          </div>
        </div>

    <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">⚠️</div>
            <div>
      <p className="text-muted-foreground text-sm">Total Vulnerabilities</p>
              <p className="text-2xl font-bold text-red-600">{totalVulns}</p>
            </div>
          </div>
        </div>

    <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">✅</div>
            <div>
      <p className="text-muted-foreground text-sm">Success Rate</p>
              <p className="text-2xl font-bold text-green-600">{safeAnalytics.scan_success_rate}%</p>
            </div>
          </div>
        </div>

    <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">📅</div>
            <div>
      <p className="text-muted-foreground text-sm">Today's Scans</p>
      <p className="text-2xl font-bold text-blue-500">{latestDay?.total_scans || 0}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Vulnerabilities by Type (Pie) */}
    <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
    <h3 className="text-lg font-semibold text-foreground">🧩 Vulnerabilities by Type</h3>
            <span className="text-sm text-muted-foreground">Total: {totalVulns}</span>
          </div>
          {!hasData ? (
            <div className="text-muted-foreground text-sm">No vulnerability data yet</div>
          ) : vulnByType.length === 0 ? (
            <div className="text-muted-foreground text-sm">No classified vulnerability types</div>
          ) : (
            <div className="w-full h-80">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={vulnByType}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={110}
                    paddingAngle={2}
                    label={false}
                    labelLine={false}
                  >
                    {vulnByType.map((entry, index) => (
                      <Cell key={`cell-${entry.key || entry.name}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value: number) => [value, 'Count']}
                    wrapperStyle={{ pointerEvents: 'auto' }}
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      borderColor: 'hsl(var(--border))',
                      fontWeight: 500,
                      fontSize: '1rem',
                    }}
                    itemStyle={{ color: '#fff' }}
                    labelStyle={{ color: '#fff' }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    wrapperStyle={{ color: 'hsl(var(--card-foreground))', fontSize: '12px' }}
                    formatter={(value: string) => {
                      const entry = vulnByType.find(v => v.name === value);
                      if (!entry) return value;
                      const pct = ((entry.value / (totalVulns || 1)) * 100).toFixed(0);
                      return `${value} (${pct}%)`;
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
        {/* Vulnerability Types (Progress bars) */}
        <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4 text-foreground">🛡️ Vulnerability Types</h3>
          <div className="space-y-3">
            {(() => {
              const ORDER = [
                'xss','sqli','csrf','ssrf','security_misconfiguration','vulnerable_components',
                'broken_access_control','cryptographic_failures','authentication_failures','integrity_failures','logging_monitoring_failures'
              ];
              const LABELS: Record<string, string> = {
                xss: 'XSS', sqli: 'SQLi', csrf: 'CSRF', ssrf: 'SSRF',
                security_misconfiguration: 'Security Misconfiguration',
                vulnerable_components: 'Vulnerable Components',
                broken_access_control: 'Broken Access Control',
                cryptographic_failures: 'Cryptographic Failures',
                authentication_failures: 'Authentication Failures',
                integrity_failures: 'Integrity Failures',
                logging_monitoring_failures: 'Logging & Monitoring Failures'
              };
              const map = new Map<string, number>();
              vulnByType.forEach(v => map.set((v as any).key || v.name.toLowerCase(), v.value));
              return ORDER.map((k, idx) => {
                const value = map.get(k) || 0;
                const percentage = totalVulns > 0 ? ((value / totalVulns) * 100).toFixed(1) : '0';
                const color = COLORS[idx % COLORS.length];
                return (
                  <div key={k} className="flex items-center justify-between">
                    <span className="text-sm font-medium text-foreground capitalize">{LABELS[k] || k}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-32 bg-muted rounded-full h-2">
                        <div
                          className="h-2 rounded-full"
                          style={{ width: `${percentage}%`, backgroundColor: color }}
                        ></div>
                      </div>
                      <span className="text-sm text-muted-foreground w-12 text-right">{value}</span>
                    </div>
                  </div>
                );
              });
            })()}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4 text-foreground">⚡ Severity Distribution</h3>
          <div className="space-y-3">
            {!hasData ? (
              <div className="text-muted-foreground text-sm">No severity data yet</div>
            ) : Object.keys(severityDist).length === 0 ? (
              <div className="text-muted-foreground text-sm">No severity distribution</div>
            ) : (
              Object.entries(severityDist).map(([severity, count]) => {
                const percentage = totalVulns > 0 ? (count / totalVulns * 100).toFixed(1) : '0';
                const severityColor = {
                  'critical': 'bg-red-500',
                  'high': 'bg-orange-500',
                  'medium': 'bg-yellow-500',
                  'low': 'bg-blue-500',
                  'info': 'bg-gray-500'
                }[severity.toLowerCase()] || 'bg-gray-500';
              
                return (
                  <div key={severity} className="flex items-center justify-between">
                    <span className="text-sm font-medium text-foreground capitalize">{severity}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-32 bg-muted rounded-full h-2">
                        <div
                          className={`${severityColor} h-2 rounded-full`}
                          style={{ width: `${percentage}%` }}
                        ></div>
                      </div>
                      <span className="text-sm text-muted-foreground w-12 text-right">{count}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Recent Trends */}
        <div className="bg-card text-card-foreground rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4 text-foreground">📈 Recent Activity</h3>
          <div className="space-y-3">
            {safeAnalytics.daily_data.slice(-7).reverse().map((day) => {
              const totalVulnsDay = Object.values(day.vulnerabilities_found || {}).reduce((sum, count) => sum + count, 0);
              const successRate = day.total_scans > 0 ? ((day.completed_scans / day.total_scans) * 100).toFixed(0) : '0';
              
              return (
                <div key={day.date} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                  <div>
                    <p className="text-sm font-medium text-foreground">
                      {new Date(day.date).toLocaleDateString()}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {day.total_scans} scans • {successRate}% success
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-red-500">{totalVulnsDay}</p>
                    <p className="text-xs text-muted-foreground">vulnerabilities</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Date Range Info */}
  <div className="mt-8 text-center text-sm text-muted-foreground">
  {hasData ? `Data for ${safeAnalytics.date_range}` : 'No historical analytics yet'}
      </div>
    </div>
  );
};
