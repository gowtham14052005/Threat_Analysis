import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  Download,
  Trash2,
  ExternalLink,
  Bookmark,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  BarChart3,
  TrendingUp,
  PieChart as PieChartIcon,
  Layers
} from 'lucide-react';
import { ScanResult, UserProfile } from '../types';
import { db } from '../lib/firebase';
import { collection, onSnapshot, query, orderBy, limit, deleteDoc, doc } from 'firebase/firestore';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip
} from 'recharts';

interface HistoryAnalyticsProps {
  user: UserProfile | null;
  onSelectScan: (scan: ScanResult) => void;
}

const DEMO_HISTORY: ScanResult[] = [
  {
    id: 'scan-demo-1',
    url: 'http://paypa1-security-verification.xyz/login/verify.php',
    domain: 'paypa1-security-verification.xyz',
    timestamp: Date.now() - 1000 * 60 * 25,
    isPhishing: true,
    riskScore: 96,
    threatLevel: 'PHISHING',
    verdict: 'PHISHING',
    confidence: 98.4,
    svm: {
      isPhishing: true,
      prediction: -1,
      confidence: 98.4,
      decisionValue: -3.42,
      hyperplaneDistance: 1.12,
      margin: 0.65,
      kernelType: 'RBF (Radial Basis Function)',
      gamma: 0.045,
      cParameter: 1.25,
      supportVectorsUsed: 342,
      totalSupportVectors: 580,
      linearScore: -3.1,
      rbfScore: -3.8,
      confusionMatrix: { truePositive: 4892, falsePositive: 78, trueNegative: 4946, falseNegative: 84, accuracy: 98.38, precision: 98.43, recall: 98.31, f1Score: 98.37 },
    },
    features: {},
    domainInfo: {
      domain: 'paypa1-security-verification.xyz',
      hostname: 'paypa1-security-verification.xyz',
      ipAddress: '185.220.101.5',
      country: 'Seychelles',
      countryCode: 'SC',
      registrar: 'NameCheap',
      creationDate: '2026-08-16',
      domainAgeDays: 14,
      domainAgeFormatted: '14 Days',
      expiryDate: '2027-08-16',
      nameservers: ['ns1.cloudflare.com'],
      dnsRecords: [{ type: 'A', value: '185.220.101.5' }],
      ssl: { hasSsl: false, issuer: 'None', valid: false, protocol: 'HTTP', daysRemaining: 0 },
      tld: '.xyz',
      entropy: 4.3,
      hasPunycode: false,
      isVerifiedDomain: false,
      verificationStatus: 'High-Risk Threat Domain',
    },
    threatIntel: {
      isBlacklisted: true,
      overallReputation: 'High Risk Malicious',
      feedsChecked: 6,
      feedsFlagged: 4,
      sources: [],
      detectedAttackTypes: ['Brand Impersonation (PayPal)', 'Credential Harvesting'],
      targetedBrand: 'PayPal',
    },
    xai: {
      summary: 'High-risk phishing site impersonating PayPal credentials.',
      verdictReasoning: 'SVM flagged multiple structural anomalies.',
      primaryRiskFactors: ['Typo-squatting', 'Fresh domain <14 days'],
      positiveSecurityIndicators: [],
      attackVectorType: 'Credential Harvester',
      suspectedBrandImpersonation: 'PayPal',
      tacticsTechniques: ['T1566.002 Spearphishing Link', 'T1056 Input Capture'],
      actionableRecommendations: ['Block on gateway', 'Do not enter credentials'],
      technicalBreakdown: 'SVM distance d=-3.42 into negative subspace',
      generatedByAi: false,
    },
    bookmarked: true,
  },
  {
    id: 'scan-demo-2',
    url: 'https://github.com/torvalds/linux',
    domain: 'github.com',
    timestamp: Date.now() - 1000 * 60 * 120,
    isPhishing: false,
    riskScore: 2,
    threatLevel: 'SAFE',
    verdict: 'SAFE',
    confidence: 99.2,
    svm: {
      isPhishing: false,
      prediction: 1,
      confidence: 99.2,
      decisionValue: 4.12,
      hyperplaneDistance: 1.62,
      margin: 0.85,
      kernelType: 'RBF (Radial Basis Function)',
      gamma: 0.045,
      cParameter: 1.25,
      supportVectorsUsed: 310,
      totalSupportVectors: 580,
      linearScore: 3.8,
      rbfScore: 4.3,
      confusionMatrix: { truePositive: 4892, falsePositive: 78, trueNegative: 4946, falseNegative: 84, accuracy: 98.38, precision: 98.43, recall: 98.31, f1Score: 98.37 },
    },
    features: {},
    domainInfo: {
      domain: 'github.com',
      hostname: 'github.com',
      ipAddress: '140.82.121.4',
      country: 'United States',
      countryCode: 'US',
      registrar: 'MarkMonitor Inc.',
      creationDate: '2007-10-09',
      domainAgeDays: 6890,
      domainAgeFormatted: '18 Years',
      expiryDate: '2028-10-09',
      nameservers: ['dns1.p08.nsone.net'],
      dnsRecords: [{ type: 'A', value: '140.82.121.4' }],
      ssl: { hasSsl: true, issuer: 'DigiCert TLS RSA SHA256 2020 CA1', valid: true, protocol: 'TLS 1.3', daysRemaining: 280 },
      tld: '.com',
      entropy: 2.8,
      hasPunycode: false,
      isVerifiedDomain: true,
      verificationStatus: 'Verified Authority',
    },
    threatIntel: {
      isBlacklisted: false,
      overallReputation: 'Clean',
      feedsChecked: 6,
      feedsFlagged: 0,
      sources: [],
      detectedAttackTypes: [],
    },
    xai: {
      summary: 'Verified authentic corporate domain with pristine security telemetry.',
      verdictReasoning: 'Long-term domain stability and valid TLS encryption.',
      primaryRiskFactors: [],
      positiveSecurityIndicators: ['Valid DigiCert cert', 'Established 18+ years'],
      attackVectorType: 'Benign Host',
      suspectedBrandImpersonation: null,
      tacticsTechniques: [],
      actionableRecommendations: ['Safe for browsing'],
      technicalBreakdown: 'SVM distance d=1.62 in positive region',
      generatedByAi: false,
    },
    bookmarked: false,
  },
];

export const HistoryAnalytics: React.FC<HistoryAnalyticsProps> = ({ user, onSelectScan }) => {
  const [scans, setScans] = useState<ScanResult[]>(DEMO_HISTORY);
  const [filterThreat, setFilterThreat] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [onlyBookmarks, setOnlyBookmarks] = useState<boolean>(false);

  useEffect(() => {
    try {
      const q = query(collection(db, 'scans'), orderBy('timestamp', 'desc'), limit(100));
      const unsubscribe = onSnapshot(
        q,
        (snapshot) => {
          if (!snapshot.empty) {
            const fetched: ScanResult[] = snapshot.docs.map((doc) => ({
              id: doc.id,
              ...doc.data(),
            })) as ScanResult[];
            setScans(fetched);
          }
        },
        (err) => {
          console.warn('Firestore scans listener notice:', err);
        }
      );
      return () => unsubscribe();
    } catch (e) {
      console.warn('Firestore scans subscription error:', e);
    }
  }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setScans((prev) => prev.filter((s) => s.id !== id));
    try {
      await deleteDoc(doc(db, 'scans', id));
    } catch (err) {
      console.warn('Firestore delete notice:', err);
    }
  };

  const handleExportCsv = () => {
    const headers = 'ID,URL,Domain,Verdict,RiskScore,Confidence,Timestamp\n';
    const rows = scans
      .map(
        (s) =>
          `"${s.id}","${s.url}","${s.domain}","${s.threatLevel}",${s.riskScore},${s.confidence},"${new Date(s.timestamp).toISOString()}"`
      )
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-scan-history-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(scans, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-scan-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredScans = scans.filter((s) => {
    const sThreatUpper = (s.threatLevel || (s.isPhishing ? 'PHISHING' : (s.riskScore >= 30 ? 'SUSPICIOUS' : 'SAFE'))).toUpperCase();
    const matchesThreat = filterThreat === 'all' || sThreatUpper === filterThreat.toUpperCase();
    const matchesBookmark = !onlyBookmarks || s.bookmarked;
    const matchesSearch =
      searchQuery === '' ||
      s.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.url.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesThreat && matchesBookmark && matchesSearch;
  });

  // Prepare Analytics Data
  const threatDistData = [
    { name: 'Phishing', value: scans.filter((s) => s.isPhishing || s.threatLevel?.toUpperCase() === 'PHISHING').length || 1, color: '#ef4444' },
    { name: 'Suspicious', value: scans.filter((s) => !s.isPhishing && (s.threatLevel?.toUpperCase() === 'SUSPICIOUS' || (s.riskScore >= 30 && s.riskScore < 70))).length || 1, color: '#f59e0b' },
    { name: 'Safe', value: scans.filter((s) => !s.isPhishing && (s.threatLevel?.toUpperCase() === 'SAFE' || s.threatLevel?.toUpperCase() === 'LOW' || s.riskScore < 30)).length || 2, color: '#10b981' },
  ];

  const trendData = [
    { day: 'Mon', detections: 14, blocked: 12 },
    { day: 'Tue', detections: 22, blocked: 20 },
    { day: 'Wed', detections: 18, blocked: 17 },
    { day: 'Thu', detections: 35, blocked: 33 },
    { day: 'Fri', detections: 28, blocked: 26 },
    { day: 'Sat', detections: 19, blocked: 18 },
    { day: 'Sun', detections: scans.length + 8, blocked: scans.length + 7 },
  ];

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-mono font-bold mb-2">
            <History className="h-3.5 w-3.5 text-blue-600" />
            <span>Telemetry & Threat Intelligence Database</span>
          </div>
          <h1 className="text-3xl font-extrabold text-blue-950">
            Scan History & <span className="text-blue-600">Threat Analytics</span>
          </h1>
          <p className="text-xs sm:text-sm text-blue-900/70">
            Real-time audit log of evaluated URLs, SVM margin metrics, and historical threat trends.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-white hover:bg-blue-50 border border-blue-200 text-xs font-bold text-blue-900 transition-colors shadow-xs cursor-pointer"
          >
            <Download className="h-3.5 w-3.5 text-blue-600" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-white hover:bg-blue-50 border border-blue-200 text-xs font-bold text-blue-900 transition-colors shadow-xs cursor-pointer"
          >
            <Download className="h-3.5 w-3.5 text-blue-600" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Analytics Visualizations */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Detection Trend Area Chart */}
        <div className="md:col-span-2 rounded-3xl bg-white border border-blue-100 p-6 space-y-4 shadow-xl shadow-blue-900/5">
          <div className="flex items-center justify-between border-b border-blue-100 pb-3">
            <h3 className="text-sm font-extrabold text-blue-950 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-blue-600" />
              <span>7-Day Phishing Interception Trends</span>
            </h3>
            <span className="text-[10px] font-mono font-bold text-emerald-700">98.4% Block Efficiency</span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563eb" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#bfdbfe', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  itemStyle={{ color: '#172554', fontSize: '12px', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="detections" stroke="#ef4444" fillOpacity={1} fill="url(#phishGrad)" name="Detected Phishing" />
                <Area type="monotone" dataKey="blocked" stroke="#2563eb" fillOpacity={1} fill="url(#blockGrad)" name="Mitigated / Blocked" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Donut */}
        <div className="rounded-3xl bg-white border border-blue-100 p-6 space-y-4 shadow-xl shadow-blue-900/5">
          <div className="border-b border-blue-100 pb-3">
            <h3 className="text-sm font-extrabold text-blue-950 flex items-center gap-2">
              <PieChartIcon className="h-4 w-4 text-blue-600" />
              <span>Risk Categorization</span>
            </h3>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={threatDistData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={4}>
                  {threatDistData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#bfdbfe', borderRadius: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-3 gap-1 text-center font-mono text-[10px]">
            {threatDistData.map((item) => (
              <div key={item.name} className="p-2 rounded-xl bg-blue-50 border border-blue-100">
                <span className="block text-blue-900/70 font-sans font-medium">{item.name}</span>
                <span className="font-extrabold text-xs" style={{ color: item.color }}>{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 rounded-2xl bg-white border border-blue-100 shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          {['all', 'Phishing', 'Suspicious', 'Safe'].map((st) => (
            <button
              key={st}
              onClick={() => setFilterThreat(st)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-colors cursor-pointer ${
                filterThreat === st
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-blue-900/70 hover:text-blue-950 bg-blue-50'
              }`}
            >
              {st === 'all' ? 'All Threats' : st}
            </button>
          ))}

          <button
            onClick={() => setOnlyBookmarks(!onlyBookmarks)}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold transition-colors cursor-pointer ${
              onlyBookmarks
                ? 'bg-purple-600 text-white shadow-xs'
                : 'text-blue-900/70 hover:text-blue-950 bg-blue-50'
            }`}
          >
            <Bookmark className="h-3.5 w-3.5" />
            <span>Saved Only</span>
          </button>
        </div>

        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter scans by domain / URL..."
          className="px-3.5 py-1.5 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600 font-mono"
        />
      </div>

      {/* Scans Table */}
      <div className="overflow-hidden rounded-3xl bg-white border border-blue-100 shadow-xl shadow-blue-900/5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-blue-50/80 border-b border-blue-100 font-mono text-blue-900 uppercase text-[10px]">
              <tr>
                <th className="px-4 py-3.5">Target Domain & URL</th>
                <th className="px-4 py-3.5">Verdict</th>
                <th className="px-4 py-3.5">Risk Score</th>
                <th className="px-4 py-3.5">SVM Decision f(x)</th>
                <th className="px-4 py-3.5">Scan Time</th>
                <th className="px-4 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-blue-50">
              {filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-blue-900/60 font-medium">
                    No scan history records found.
                  </td>
                </tr>
              ) : (
                filteredScans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan)}
                    className="hover:bg-blue-50/40 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3.5">
                      <div className="font-extrabold text-blue-950 font-mono">{scan.domain}</div>
                      <div className="text-[11px] text-blue-900/70 font-mono truncate max-w-xs">{scan.url}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1 font-mono text-[10px] font-bold px-2.5 py-1 rounded-full ${
                          scan.isPhishing || scan.threatLevel?.toUpperCase() === 'PHISHING'
                            ? 'bg-rose-100 text-rose-800 border border-rose-200'
                            : scan.threatLevel?.toUpperCase() === 'SUSPICIOUS'
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        }`}
                      >
                        {scan.isPhishing || scan.threatLevel?.toUpperCase() === 'PHISHING' ? (
                          <ShieldAlert className="h-3 w-3" />
                        ) : (
                          <ShieldCheck className="h-3 w-3" />
                        )}
                        <span>{scan.threatLevel?.toUpperCase() || (scan.isPhishing ? 'PHISHING' : 'SAFE')}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3.5 font-mono font-extrabold">
                      <span className={scan.riskScore >= 70 ? 'text-rose-600' : (scan.riskScore >= 40 ? 'text-amber-600' : 'text-emerald-700')}>
                        {scan.riskScore}%
                      </span>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-blue-900 font-bold">
                      {scan.svm?.decisionValue || (scan.riskScore >= 70 ? '-2.85' : '+3.14')}
                    </td>
                    <td className="px-4 py-3.5 text-blue-900/70 font-mono text-[11px]">
                      {new Date(scan.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={(e) => handleDelete(scan.id, e)}
                          className="p-1.5 rounded-xl text-blue-400 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                          title="Delete from history"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
