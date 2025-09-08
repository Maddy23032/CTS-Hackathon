import React from 'react';
import { ScanHistory } from './history';
import { VulnerabilitySearch } from './search';
import { Analytics } from './analytics';

/**
 * Test component to demonstrate MongoDB integration features
 * This is a simple demo page that can be added to your app for testing
 */
export default function MongoDBTestPage() {
  const [activeTab, setActiveTab] = React.useState('history');

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">
            VulnScan MongoDB Integration Test
          </h1>
          <p className="mt-2 text-lg text-gray-600">
            Testing all MongoDB features: Scan History, Vulnerability Search, and Analytics
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="mb-8">
          <nav className="flex space-x-8" aria-label="Tabs">
            {[
              { id: 'history', name: 'Scan History' },
              { id: 'search', name: 'Vulnerability Search' },
              { id: 'analytics', name: 'Analytics' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="bg-white shadow rounded-lg">
          {activeTab === 'history' && (
            <div className="p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Scan History
              </h2>
              <ScanHistory />
            </div>
          )}

          {activeTab === 'search' && (
            <div className="p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Vulnerability Search
              </h2>
              <VulnerabilitySearch />
            </div>
          )}

          {activeTab === 'analytics' && (
            <div className="p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Analytics Dashboard
              </h2>
              <Analytics />
            </div>
          )}
        </div>

        {/* Instructions */}
        <div className="mt-8 bg-blue-50 border border-blue-200 rounded-lg p-6">
          <h3 className="text-lg font-medium text-blue-900 mb-2">
            Testing Instructions
          </h3>
          <div className="text-blue-800 space-y-2">
            <p>1. Make sure MongoDB is running and the backend server is started</p>
            <p>2. Run some scans to generate data for testing</p>
            <p>3. Test each tab to verify all features work correctly:</p>
            <ul className="list-disc list-inside ml-4 space-y-1">
              <li><strong>Scan History:</strong> View past scans with pagination and filtering</li>
              <li><strong>Vulnerability Search:</strong> Search and filter vulnerabilities with real-time results</li>
              <li><strong>Analytics:</strong> View dashboard with scan statistics and trends</li>
            </ul>
          </div>
        </div>

        {/* API Status */}
        <div className="mt-4 bg-gray-50 border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-medium text-gray-900 mb-2">API Endpoints:</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-gray-600">
            <div>
              <code className="bg-gray-100 px-2 py-1 rounded">GET /api/scan/history</code>
              <p>Paginated scan history</p>
            </div>
            <div>
              <code className="bg-gray-100 px-2 py-1 rounded">GET /api/vulnerabilities/search</code>
              <p>Search vulnerabilities</p>
            </div>
            <div>
              <code className="bg-gray-100 px-2 py-1 rounded">GET /api/analytics</code>
              <p>Analytics dashboard data</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
