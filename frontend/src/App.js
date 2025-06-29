import React, { useState, useEffect } from "react";
import "./App.css";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ThreatHeatmap = ({ emailContent, threats }) => {
  if (!threats || threats.length === 0) {
    return (
      <div className="bg-green-50 border border-green-200 rounded-lg p-4">
        <div className="text-green-800 font-medium">✅ No threats detected</div>
        <div className="text-green-600 text-sm mt-1">This email appears to be safe</div>
      </div>
    );
  }

  // Create highlighted version of email content
  const createHighlightedContent = () => {
    let highlightedContent = emailContent;
    const sortedThreats = [...threats].sort((a, b) => b.start_pos - a.start_pos);
    
    sortedThreats.forEach((threat) => {
      const threatText = emailContent.substring(threat.start_pos, threat.end_pos);
      const threatLevel = getThreatColor(threat.confidence);
      const highlightedText = `<span class="threat-highlight ${threatLevel}" data-threat="${threat.threat_type}" data-confidence="${threat.confidence}" title="${threat.description}">${threatText}</span>`;
      
      highlightedContent = 
        highlightedContent.substring(0, threat.start_pos) + 
        highlightedText + 
        highlightedContent.substring(threat.end_pos);
    });

    return highlightedContent;
  };

  const getThreatColor = (confidence) => {
    if (confidence >= 80) return 'threat-critical';
    if (confidence >= 60) return 'threat-high';
    if (confidence >= 40) return 'threat-medium';
    return 'threat-low';
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Email Content Analysis</h3>
      <div 
        className="email-content-heatmap text-sm leading-relaxed whitespace-pre-wrap"
        dangerouslySetInnerHTML={{ __html: createHighlightedContent() }}
      />
      
      <div className="mt-4 pt-4 border-t border-gray-200">
        <h4 className="font-medium text-gray-900 mb-2">Threat Legend:</h4>
        <div className="flex flex-wrap gap-4 text-xs">
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-red-500 rounded"></div>
            <span>Critical (80-100%)</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-orange-500 rounded"></div>
            <span>High (60-79%)</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-yellow-500 rounded"></div>
            <span>Medium (40-59%)</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-blue-500 rounded"></div>
            <span>Low (0-39%)</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const ThreatSummary = ({ analysis, onReport }) => {
  const getThreatLevelColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getThreatIcon = (level) => {
    switch (level) {
      case 'CRITICAL': return '🚨';
      case 'HIGH': return '⚠️';
      case 'MEDIUM': return '⚡';
      case 'LOW': return '✅';
      default: return '🔍';
    }
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Threat Analysis Summary</h3>
        <div className={`px-3 py-1 rounded-full border text-sm font-medium ${getThreatLevelColor(analysis.threat_level)}`}>
          {getThreatIcon(analysis.threat_level)} {analysis.threat_level}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{analysis.overall_threat_score}/100</div>
          <div className="text-sm text-gray-600">Overall Threat Score</div>
        </div>
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{analysis.threats_detected.length}</div>
          <div className="text-sm text-gray-600">Threats Detected</div>
        </div>
      </div>

      <div className="mb-4">
        <h4 className="font-medium text-gray-900 mb-2">Analysis Summary:</h4>
        <p className="text-gray-700 text-sm">{analysis.analysis_summary}</p>
      </div>

      {analysis.threats_detected.length > 0 && (
        <div className="mb-4">
          <h4 className="font-medium text-gray-900 mb-2">Detected Threats:</h4>
          <div className="space-y-2">
            {analysis.threats_detected.map((threat, index) => (
              <div key={index} className="bg-red-50 border border-red-200 rounded-lg p-3">
                <div className="flex justify-between items-start mb-1">
                  <span className="font-medium text-red-800">{threat.threat_type.replace('_', ' ')}</span>
                  <span className="text-xs bg-red-100 text-red-700 px-2 py-1 rounded">{threat.confidence}%</span>
                </div>
                <p className="text-sm text-red-700 mb-1">"{threat.text}"</p>
                <p className="text-xs text-red-600">{threat.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {analysis.overall_threat_score > 40 && (
        <div className="pt-4 border-t border-gray-200">
          <button
            onClick={() => onReport(analysis.id)}
            className="w-full bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors font-medium"
          >
            🚨 Report as Phishing
          </button>
        </div>
      )}
    </div>
  );
};

function App() {
  const [emailContent, setEmailContent] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentAnalyses, setRecentAnalyses] = useState([]);

  const analyzeEmail = async () => {
    if (!emailContent.trim()) {
      alert('Please enter email content to analyze');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze-email`, {
        email_content: emailContent
      });
      setAnalysis(response.data);
      loadRecentAnalyses();
    } catch (error) {
      console.error('Analysis failed:', error);
      alert('Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const reportPhishing = async (analysisId) => {
    try {
      await axios.post(`${API}/report-phishing?analysis_id=${analysisId}&user_notes=Reported via SecureMail`);
      alert('Phishing report submitted successfully!');
    } catch (error) {
      console.error('Report failed:', error);
      alert('Failed to submit report. Please try again.');
    }
  };

  const loadRecentAnalyses = async () => {
    try {
      const response = await axios.get(`${API}/analyses?limit=5`);
      setRecentAnalyses(response.data);
    } catch (error) {
      console.error('Failed to load recent analyses:', error);
    }
  };

  const clearAnalysis = () => {
    setAnalysis(null);
    setEmailContent('');
  };

  useEffect(() => {
    loadRecentAnalyses();
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-600 text-white p-2 rounded-lg">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">SecureMail</h1>
                <p className="text-sm text-gray-600">AI-Powered Email Threat Detector</p>
              </div>
            </div>
            <div className="text-sm text-gray-500">Powered by GPT-4o</div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Input Section */}
          <div className="lg:col-span-2">
            <div className="bg-white border border-gray-200 rounded-lg p-6 mb-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Email Content Analysis</h2>
              <textarea
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="Paste your email content here for threat analysis..."
                className="w-full h-64 p-4 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <div className="flex justify-between items-center mt-4">
                <div className="text-sm text-gray-500">
                  {emailContent.length} characters
                </div>
                <div className="space-x-2">
                  {analysis && (
                    <button
                      onClick={clearAnalysis}
                      className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                    >
                      Clear
                    </button>
                  )}
                  <button
                    onClick={analyzeEmail}
                    disabled={loading || !emailContent.trim()}
                    className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
                  >
                    {loading ? '🔍 Analyzing...' : '🔍 Analyze Email'}
                  </button>
                </div>
              </div>
            </div>

            {/* Analysis Results */}
            {analysis && (
              <div className="space-y-6">
                <ThreatHeatmap emailContent={emailContent} threats={analysis.threats_detected} />
                <ThreatSummary analysis={analysis} onReport={reportPhishing} />
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white border border-gray-200 rounded-lg p-6 mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">How it Works</h3>
              <div className="space-y-3 text-sm text-gray-600">
                <div className="flex items-start space-x-2">
                  <span className="bg-blue-100 text-blue-600 rounded-full w-6 h-6 flex items-center justify-center text-xs font-medium">1</span>
                  <span>Paste your email content in the text area</span>
                </div>
                <div className="flex items-start space-x-2">
                  <span className="bg-blue-100 text-blue-600 rounded-full w-6 h-6 flex items-center justify-center text-xs font-medium">2</span>
                  <span>Our AI analyzes for phishing, scams, and malicious content</span>
                </div>
                <div className="flex items-start space-x-2">
                  <span className="bg-blue-100 text-blue-600 rounded-full w-6 h-6 flex items-center justify-center text-xs font-medium">3</span>
                  <span>View visual heatmap highlighting risky areas</span>
                </div>
                <div className="flex items-start space-x-2">
                  <span className="bg-blue-100 text-blue-600 rounded-full w-6 h-6 flex items-center justify-center text-xs font-medium">4</span>
                  <span>Report threats with one click if needed</span>
                </div>
              </div>
            </div>

            {/* Recent Analyses */}
            {recentAnalyses.length > 0 && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Analyses</h3>
                <div className="space-y-3">
                  {recentAnalyses.map((recent) => (
                    <div key={recent.id} className="border border-gray-200 rounded-lg p-3">
                      <div className="flex justify-between items-center mb-1">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${recent.threat_level === 'HIGH' || recent.threat_level === 'CRITICAL' ? 'bg-red-100 text-red-800' : recent.threat_level === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
                          {recent.threat_level}
                        </span>
                        <span className="text-xs text-gray-500">{recent.overall_threat_score}/100</span>
                      </div>
                      <p className="text-xs text-gray-600 truncate">
                        {recent.email_content.substring(0, 100)}...
                      </p>
                      <p className="text-xs text-gray-500 mt-1">
                        {new Date(recent.timestamp).toLocaleDateString()}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;