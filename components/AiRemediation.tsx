import React, { useState, useCallback } from 'react';
import type { Vulnerability } from '../types';
import { fetchRemediation } from '../services/remediationService';

interface AiRemediationProps {
  vulnerability: Vulnerability;
}

const LoadingSpinner: React.FC = () => (
    <div className="flex items-center space-x-2">
        <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse [animation-delay:-0.3s]"></div>
        <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse [animation-delay:-0.15s]"></div>
        <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></div>
        <span className="text-sm text-gray-400">AI is thinking...</span>
    </div>
);


const AiRemediation: React.FC<AiRemediationProps> = ({ vulnerability }) => {
  const [remediation, setRemediation] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateRemediation = useCallback(async () => {
    setIsLoading(true);
    setError(null);
  setRemediation('');

    const promptDetails = `
      Vulnerability Name: ${vulnerability.name}
      Type: ${vulnerability.type}
      CVSS Score: ${vulnerability.cvss.score}
      Description: ${vulnerability.description}
      Evidence (vulnerable code snippet):
      File: ${vulnerability.evidence.file}
      Line: ${vulnerability.evidence.lineNumber}
      \`\`\`
      ${vulnerability.evidence.codeSnippet}
      \`\`\`
    `;

    try {
  const result = await fetchRemediation(vulnerability);
      setRemediation(result);
    } catch (e:any) {
      console.error(e);
      setError(`Failed to generate remediation: ${e.message || e}`);
    } finally {
      setIsLoading(false);
    }
  }, [vulnerability]);

  return (
    <div className="mt-6 border-t border-gray-700 pt-6">
      <h3 className="font-semibold text-gray-300 mb-2 flex items-center">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5 mr-2 text-cyan-400">
            <path fillRule="evenodd" d="M15.312 5.125a3.125 3.125 0 1 1-6.25 0 3.125 3.125 0 0 1 6.25 0ZM11.25 8.75a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5a.75.75 0 0 1 .75-.75Zm0 8.125a.625.625 0 1 0 0-1.25.625.625 0 0 0 0 1.25ZM3.125 5.125a3.125 3.125 0 1 1 6.25 0 3.125 3.125 0 0 1-6.25 0ZM7.5 8.75a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5a.75.75 0 0 1 .75-.75Zm-1.875 8.125a.625.625 0 1 0 0-1.25.625.625 0 0 0 0 1.25Z" clipRule="evenodd" />
        </svg>
        AI-Powered Remediation
      </h3>
      
      {!remediation && !isLoading && (
         <div className="flex flex-col items-start">
            <p className="text-sm text-gray-400 mb-4">
                Use Gemini to generate a step-by-step remediation plan for this vulnerability based on the evidence provided.
            </p>
            <button
                onClick={handleGenerateRemediation}
                disabled={isLoading}
                className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg transition-colors duration-200 flex items-center"
                >
                Generate Plan
            </button>
         </div>
      )}

      {isLoading && <LoadingSpinner />}
      
      {error && <p className="text-red-400 text-sm bg-red-500/10 p-3 rounded-lg">{error}</p>}
      
      {remediation && (
        <div className="prose prose-sm prose-invert max-w-none text-gray-300 bg-gray-900/50 p-4 rounded-lg mt-2">
          <pre className="whitespace-pre-wrap bg-transparent p-0 font-sans">{remediation}</pre>
        </div>
      )}
    </div>
  );
};

export default AiRemediation;