// ScanHistory.tsx
// Component for displaying scan history with filtering and pagination

import React, { useState, useEffect } from 'react';
import { apiService, type Scan, type ScanHistoryResponse } from '../../lib/api';

export const ScanHistory: React.FC = () => {
  const [scanHistory, setScanHistory] = useState<ScanHistoryResponse>({
    scans: [],
    total: 0,
    page: 1,
    per_page: 20,
    total_pages: 0
  });
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState({
    status: '',
    target_url: '',
    scan_type: ''
  });

  const fetchScanHistory = async () => {
    setLoading(true);
    try {
      const data = await apiService.getScanHistory({
        page: currentPage,
        per_page: 20,
        ...(filters.status && { status: filters.status }),
        ...(filters.target_url && { target_url: filters.target_url }),
        ...(filters.scan_type && { scan_type: filters.scan_type })
      });
      setScanHistory(data);
    } catch (error) {
      console.error('Failed to fetch scan history:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanHistory();
  }, [currentPage, filters]);

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed': return 'bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs';
      case 'running': return 'bg-blue-100 text-blue-800 px-2 py-1 rounded-full text-xs';
      case 'failed': return 'bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs';
      case 'stopped': return 'bg-yellow-100 text-yellow-800 px-2 py-1 rounded-full text-xs';
      default: return 'bg-gray-100 text-gray-800 px-2 py-1 rounded-full text-xs';
    }
  };

  const getSeverityColor = (count: number) => {
    if (count === 0) return 'text-green-600';
    if (count <= 5) return 'text-yellow-600';
    return 'text-red-600';
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setFilters({
      status: '',
      target_url: '',
      scan_type: ''
    });
    setCurrentPage(1);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="bg-white rounded-lg shadow-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            🕒 Scan History
          </h2>
        </div>
        
        <div className="p-6">
          {/* Filters */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Target URL</label>
              <input
                type="text"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Filter by URL..."
                value={filters.target_url}
                onChange={(e) => handleFilterChange('target_url', e.target.value)}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
              >
                <option value="">All statuses</option>
                <option value="completed">Completed</option>
                <option value="running">Running</option>
                <option value="failed">Failed</option>
                <option value="stopped">Stopped</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Scan Type</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={filters.scan_type}
                onChange={(e) => handleFilterChange('scan_type', e.target.value)}
              >
                <option value="">All types</option>
                <option value="xss">XSS</option>
                <option value="sqli">SQL Injection</option>
                <option value="csrf">CSRF</option>
              </select>
            </div>
            
            <div className="flex items-end">
              <button
                onClick={clearFilters}
                className="w-full px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
              >
                Clear Filters
              </button>
            </div>
          </div>

          {/* Results Summary */}
          <div className="mb-4 text-sm text-gray-600">
            Showing {scanHistory.scans.length} of {scanHistory.total} scans
          </div>

          {/* Scan List */}
          {loading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto"></div>
              <p className="mt-2 text-gray-600">Loading scan history...</p>
            </div>
          ) : scanHistory.scans.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              📊 No scans found matching your criteria
            </div>
          ) : (
            <div className="space-y-4">
              {scanHistory.scans.map((scan) => (
                <div key={scan.scan_id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="text-gray-500">🌐</span>
                        <span className="font-medium text-gray-900 truncate">{scan.target_url}</span>
                        <span className={getStatusColor(scan.status)}>
                          {scan.status}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-6 text-sm text-gray-600">
                        <div className="flex items-center gap-1">
                          <span>📊</span>
                          <span>{scan.scan_types.join(', ').toUpperCase()}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span>⚠️</span>
                          <span className={getSeverityColor(scan.vulnerabilities_found)}>
                            {scan.vulnerabilities_found} vulnerabilities
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span>🕒</span>
                          <span>{formatDate(scan.created_at)}</span>
                        </div>
                        {scan.total_time && (
                          <div className="flex items-center gap-1">
                            <span>⏱️</span>
                            <span>{scan.total_time}s duration</span>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex gap-2">
                      <button
                        className="px-3 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors text-sm"
                        onClick={() => {
                          // Navigate to scan details
                          window.location.href = `/scan/${scan.scan_id}`;
                        }}
                      >
                        View Details
                      </button>
                      {scan.status === 'completed' && scan.vulnerabilities_found > 0 && (
                        <button
                          className="px-3 py-1 bg-green-100 text-green-700 rounded hover:bg-green-200 transition-colors text-sm"
                          onClick={() => {
                            // Navigate to vulnerability report
                            window.location.href = `/report/${scan.scan_id}`;
                          }}
                        >
                          View Report
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {scanHistory.total_pages > 1 && (
            <div className="flex items-center justify-center gap-2 mt-6">
              <button
                className="px-3 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
              >
                Previous
              </button>
              
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(5, scanHistory.total_pages) }, (_, i) => {
                  const pageNum = Math.max(1, Math.min(
                    scanHistory.total_pages - 4,
                    Math.max(1, currentPage - 2)
                  )) + i;
                  
                  return (
                    <button
                      key={pageNum}
                      className={`px-3 py-2 rounded transition-colors ${
                        pageNum === currentPage
                          ? 'bg-blue-500 text-white'
                          : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                      }`}
                      onClick={() => setCurrentPage(pageNum)}
                    >
                      {pageNum}
                    </button>
                  );
                })}
              </div>
              
              <button
                className="px-3 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                onClick={() => setCurrentPage(prev => Math.min(scanHistory.total_pages, prev + 1))}
                disabled={currentPage === scanHistory.total_pages}
              >
                Next
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
