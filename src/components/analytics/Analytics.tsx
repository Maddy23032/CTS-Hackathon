// Analytics.tsx
// Component for displaying analytics and trends

import React, { useState, useEffect } from 'react';
import { apiService, type AnalyticsResponse } from '../../lib/api';

export const Analytics: React.FC = () => {
  const [analytics, setAnalytics] = useState<AnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(30);

  const fetchAnalytics = async () => {
    setLoading(true);
    try {
      const data = await apiService.getAnalytics(timeRange);
      setAnalytics(data);
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
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

  const getTopTargets = () => {
    if (!analytics?.daily_data) return [];
    const targetCounts: { [key: string]: number } = {};
    
    analytics.daily_data.forEach(day => {
      day.top_targets?.forEach(target => {
        targetCounts[target.url] = (targetCounts[target.url] || 0) + target.count;
      });
    });
    
    return Object.entries(targetCounts)
      .map(([url, count]) => ({ url, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
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

  if (!analytics) {
    return (
      <div className="p-6 max-w-7xl mx-auto">
        <div className="text-center py-8 text-gray-500">
          📊 No analytics data available
        </div>
      </div>
    );
  }

  const latestDay = getLatestDayData();
  const totalVulns = getTotalVulnerabilities();
  const severityDist = getTotalSeverityDistribution();
  const topTargets = getTopTargets();

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">📊 Analytics Dashboard</h1>
        
        {/* Time Range Selector */}
        <div className="flex gap-2">
          <label className="text-sm font-medium text-gray-700 self-center">Time Range:</label>
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
              {days} days
            </button>
          ))}
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">🔍</div>
            <div>
              <p className="text-gray-500 text-sm">Total Scans</p>
              <p className="text-2xl font-bold text-gray-900">{analytics.total_scans}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">⚠️</div>
            <div>
              <p className="text-gray-500 text-sm">Total Vulnerabilities</p>
              <p className="text-2xl font-bold text-red-600">{totalVulns}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">✅</div>
            <div>
              <p className="text-gray-500 text-sm">Success Rate</p>
              <p className="text-2xl font-bold text-green-600">{analytics.scan_success_rate}%</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="text-2xl mr-3">📅</div>
            <div>
              <p className="text-gray-500 text-sm">Today's Scans</p>
              <p className="text-2xl font-bold text-blue-600">{latestDay?.total_scans || 0}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Vulnerability Types Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">🛡️ Vulnerability Types</h3>
          <div className="space-y-3">
            {Object.entries(
              analytics.daily_data.reduce((acc, day) => {
                Object.entries(day.vulnerabilities_found || {}).forEach(([type, count]) => {
                  acc[type] = (acc[type] || 0) + count;
                });
                return acc;
              }, {} as { [key: string]: number })
            ).map(([type, count]) => {
              const percentage = totalVulns > 0 ? (count / totalVulns * 100).toFixed(1) : '0';
              return (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-700 capitalize">{type}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-blue-500 h-2 rounded-full"
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>
                    <span className="text-sm text-gray-600 w-12 text-right">{count}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">⚡ Severity Distribution</h3>
          <div className="space-y-3">
            {Object.entries(severityDist).map(([severity, count]) => {
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
                  <span className="text-sm font-medium text-gray-700 capitalize">{severity}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 bg-gray-200 rounded-full h-2">
                      <div
                        className={`${severityColor} h-2 rounded-full`}
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>
                    <span className="text-sm text-gray-600 w-12 text-right">{count}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Targets */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">🎯 Most Scanned Targets</h3>
          <div className="space-y-3">
            {topTargets.slice(0, 8).map(({ url, count }, index) => (
              <div key={url} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs bg-gray-100 text-gray-600 rounded-full w-6 h-6 flex items-center justify-center">
                    {index + 1}
                  </span>
                  <span className="text-sm text-gray-700 truncate max-w-xs" title={url}>
                    {url}
                  </span>
                </div>
                <span className="text-sm font-medium text-gray-900">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Trends */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">📈 Recent Activity</h3>
          <div className="space-y-3">
            {analytics.daily_data.slice(-7).reverse().map((day) => {
              const totalVulnsDay = Object.values(day.vulnerabilities_found || {}).reduce((sum, count) => sum + count, 0);
              const successRate = day.total_scans > 0 ? ((day.completed_scans / day.total_scans) * 100).toFixed(0) : '0';
              
              return (
                <div key={day.date} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      {new Date(day.date).toLocaleDateString()}
                    </p>
                    <p className="text-xs text-gray-500">
                      {day.total_scans} scans • {successRate}% success
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-red-600">{totalVulnsDay}</p>
                    <p className="text-xs text-gray-500">vulnerabilities</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Date Range Info */}
      <div className="mt-8 text-center text-sm text-gray-500">
        Data for {analytics.date_range}
      </div>
    </div>
  );
};
