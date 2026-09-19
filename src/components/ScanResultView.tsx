import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  Share2,
  Bookmark,
  FileText,
  Copy,
  Check,
  Sparkles,
  Cpu,
  Layers,
  Globe,
  Radio,
  ExternalLink,
  ShieldX,
  Lock,
  Unlock,
  AlertCircle,
  HelpCircle,
  BarChart3,
  Sliders,
  Award,
  Download,
  Printer,
  X,
  Lightbulb,
  CheckCircle2,
  XCircle,
  MessageCircle,
  Eye,
  Settings
} from 'lucide-react';
import { ScanResult, SecurityAlert, UserProfile, ExtractedFeatureItem } from '../types';
import { createAlertInFirestore, addToWatchlist } from '../lib/firebase';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

interface ScanResultViewProps {
  result: ScanResult;
  onBack?: () => void;
  onNewScan?: () => void;
  user?: UserProfile | null;
  onOpenExportModal?: () => void;
}

export const ScanResultView: React.FC<ScanResultViewProps> = ({
  result,
  onBack,
  onNewScan,
  user,
  onOpenExportModal,
}) => {
  // Mode: 'simple' for everyday users, 'pro' for deep cyber analysis
  const [viewMode, setViewMode] = useState<'simple' | 'pro'>('simple');
  const [activeTab, setActiveTab] = useState<'xai' | 'features' | 'svm' | 'whois' | 'threats'>('xai');
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedShareText, setCopiedShareText] = useState(false);
  const [alertCreated, setAlertCreated] = useState(false);
  const [watchlistStatus, setWatchlistStatus] = useState<'idle' | 'whitelist_added' | 'blacklist_added'>('idle');
  const [featureCategoryFilter, setFeatureCategoryFilter] = useState<string>('all');
  const [featureSearch, setFeatureSearch] = useState<string>('');
  const [showExportModal, setShowExportModal] = useState(false);
  const [copiedExportFormat, setCopiedExportFormat] = useState<string | null>(null);

  const handleBack = () => {
    if (onNewScan) onNewScan();
    else if (onBack) onBack();
  };

  const handleExportClick = () => {
    if (onOpenExportModal) {
      onOpenExportModal();
    } else {
      setShowExportModal(true);
    }
  };

  const isPhish = result.isPhishing || result.verdict === 'PHISHING' || result.threatLevel === 'PHISHING';
  const isSuspicious = !isPhish && (result.verdict === 'SUSPICIOUS' || result.threatLevel === 'SUSPICIOUS');
  const isSafe = !isPhish && !isSuspicious;

  const handleCopy = () => {
    navigator.clipboard.writeText(result.url);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const handleCopyShareWarning = () => {
    const statusText = isPhish
      ? '🚨 DANGEROUS PHISHING SCAM'
      : isSuspicious
      ? '⚠️ SUSPICIOUS LINK'
      : '🛡️ VERIFIED SAFE LINK';
    const msg = `PhishGuard Link Safety Check:\n\n${statusText}\nTarget: ${result.url}\nSafety Score: ${100 - result.riskScore}/100\n\n${
      isPhish
        ? 'Do NOT open this link or enter any passwords. It is designed to steal account credentials.'
        : isSuspicious
        ? 'Be careful with this link. Avoid entering credit cards or login details.'
        : 'This link was verified as authentic.'
    }`;
    navigator.clipboard.writeText(msg);
    setCopiedShareText(true);
    setTimeout(() => setCopiedShareText(false), 2500);
  };

  const handleCreateAlert = async () => {
    try {
      await createAlertInFirestore({
        userId: user?.uid || 'anonymous',
        scanId: result.id,
        url: result.url,
        domain: result.domain,
        threatType: result.xai.attackVectorType || (isPhish ? 'Phishing Malicious' : 'Suspicious Activity'),
        severity: result.riskScore >= 80 ? 'Critical' : result.riskScore >= 50 ? 'High' : 'Medium',
        status: 'Active',
        riskScore: result.riskScore,
        notes: `SVM Classifier flagged threat score of ${result.riskScore}% with ${result.confidence}% confidence.`,
      });
      setAlertCreated(true);
    } catch (err) {
      console.error('Failed to create alert:', err);
    }
  };

  const handleAddWatchlist = async (type: 'whitelist' | 'blacklist') => {
    try {
      await addToWatchlist({
        userId: user?.uid || 'anonymous',
        type,
        domainOrUrl: result.domain,
        reason: `Added from scan ${result.id} (${type.toUpperCase()})`,
      });
      setWatchlistStatus(type === 'whitelist' ? 'whitelist_added' : 'blacklist_added');
    } catch (err) {
      console.error('Failed to add to watchlist:', err);
    }
  };

  // Prepare SHAP feature impact data for chart
  const featureList: ExtractedFeatureItem[] = Object.values(result.features || {}) as ExtractedFeatureItem[];
  const topImpactFeatures = [...featureList]
    .sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact))
    .slice(0, 7)
    .map((f) => ({
      name: f.name.length > 20 ? f.name.substring(0, 18) + '...' : f.name,
      fullName: f.name,
      impact: Number(f.impact.toFixed(2)),
      score: f.score,
      isRisk: f.score === -1,
    }));

  // Filter features
  const filteredFeatures: ExtractedFeatureItem[] = featureList.filter((f) => {
    const matchesCat = featureCategoryFilter === 'all' || f.category === featureCategoryFilter;
    const matchesSearch =
      featureSearch === '' ||
      f.name.toLowerCase().includes(featureSearch.toLowerCase()) ||
      f.description.toLowerCase().includes(featureSearch.toLowerCase()) ||
      f.rationale.toLowerCase().includes(featureSearch.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const downloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `phishguard-audit-${result.domain}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const downloadCsv = () => {
    const rows = [
      ['Feature ID', 'Feature Name', 'Score', 'Value', 'Category', 'SVM Weight', 'Impact'],
      ...featureList.map((f) => [
        f.id,
        `"${f.name.replace(/"/g, '""')}"`,
        f.score,
        `"${String(f.value).replace(/"/g, '""')}"`,
        f.category,
        f.weight,
        f.impact.toFixed(3),
      ]),
    ];
    const csvContent = 'data:text/csv;charset=utf-8,' + rows.map((e) => e.join(',')).join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard-svm-features-${result.domain}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const copyMarkdown = () => {
    const md = `# PhishGuard SVM Security Analysis Report
**Target URL**: ${result.url}
**Domain**: ${result.domain}
**Scan Timestamp**: ${new Date(result.timestamp).toUTCString()}
**Verdict**: ${result.isPhishing ? '🚨 PHISHING MALICIOUS' : '🛡️ LEGITIMATE & SAFE'}
**Threat Risk Score**: ${result.riskScore}/100 (${result.threatLevel})
**SVM Classifier Confidence**: ${result.confidence}%
**SVM Hyperplane Decision f(x)**: ${result.svm.decisionValue.toFixed(4)}
**RBF Kernel Distance**: ${result.svm.rbfScore.toFixed(4)}

## Explainable AI (XAI) Summary
${result.xai.summary}

### Primary Risk Factors:
${result.xai.primaryRiskFactors.map((r) => `- ${r}`).join('\n')}

### Actionable SOC Recommendations:
${result.xai.actionableRecommendations.map((a) => `1. ${a}`).join('\n')}
`;
    navigator.clipboard.writeText(md);
    setCopiedExportFormat('md');
    setTimeout(() => setCopiedExportFormat(null), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Top Controls: Back Button & Mode Switcher */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <button
          onClick={handleBack}
          className="flex items-center gap-2 px-4 py-2.5 rounded-2xl bg-white hover:bg-blue-50 border border-blue-200 text-xs font-bold text-blue-900 shadow-xs transition-colors cursor-pointer"
        >
          <ArrowLeft className="h-4 w-4 text-blue-600" />
          <span>Scan Another Link</span>
        </button>

        {/* View Mode Switcher (Simple vs Pro) */}
        <div className="flex items-center gap-2 w-full sm:w-auto justify-between sm:justify-end">
          <div className="flex items-center p-1 rounded-xl bg-blue-50 border border-blue-200">
            <button
              onClick={() => setViewMode('simple')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                viewMode === 'simple'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-600/20'
                  : 'text-blue-900/70 hover:text-blue-950'
              }`}
            >
              <Lightbulb className="h-3.5 w-3.5" />
              <span>Easy View (For Everyone)</span>
            </button>
            <button
              onClick={() => setViewMode('pro')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                viewMode === 'pro'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-600/20'
                  : 'text-blue-900/70 hover:text-blue-950'
              }`}
            >
              <Cpu className="h-3.5 w-3.5" />
              <span>Cyber Pro / SVM Lab</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyShareWarning}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-white hover:bg-blue-50 border border-blue-200 text-xs font-bold text-blue-800 transition-colors cursor-pointer shadow-xs"
              title="Copy shareable safety warning"
            >
              {copiedShareText ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Share2 className="h-3.5 w-3.5 text-blue-600" />}
              <span>{copiedShareText ? 'Copied Summary!' : 'Share Warning'}</span>
            </button>

            <button
              onClick={handleExportClick}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-md shadow-blue-600/20 transition-all cursor-pointer"
            >
              <FileText className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Export Report</span>
            </button>
          </div>
        </div>
      </div>

      {/* Local Fallback / Offline Analysis Mode Banner */}
      {result.analysisNotice && (
        <div className="flex items-center gap-3 p-4 rounded-2xl bg-amber-50 border border-amber-200 text-amber-900 text-xs font-semibold">
          <AlertCircle className="h-4 w-4 text-amber-600 shrink-0" />
          <p className="flex-1">
            <strong>Notice:</strong> {result.analysisNotice}
          </p>
        </div>
      )}

      {/* Main Threat Verdict Header Card */}
      <div
        className={`relative overflow-hidden rounded-3xl border p-6 sm:p-8 shadow-xl shadow-blue-900/5 ${
          isPhish
            ? 'bg-gradient-to-br from-rose-50 via-white to-rose-50/40 border-rose-200'
            : isSuspicious
            ? 'bg-gradient-to-br from-amber-50 via-white to-amber-50/40 border-amber-200'
            : 'bg-gradient-to-br from-emerald-50 via-white to-emerald-50/40 border-emerald-200'
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          {/* Left Verdict Details */}
          <div className="space-y-4 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs sm:text-sm font-extrabold uppercase tracking-wider shadow-sm ${
                  isPhish
                    ? 'bg-rose-600 text-white'
                    : isSuspicious
                    ? 'bg-amber-600 text-white'
                    : 'bg-emerald-600 text-white'
                }`}
              >
                {isPhish ? (
                  <>
                    <ShieldAlert className="h-4 w-4" />
                    <span>DANGER: DANGEROUS SCAM / PHISHING DETECTED</span>
                  </>
                ) : isSuspicious ? (
                  <>
                    <AlertTriangle className="h-4 w-4" />
                    <span>CAUTION: SUSPICIOUS LINK</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-4 w-4" />
                    <span>SAFE: VERIFIED LEGITIMATE WEBSITE</span>
                  </>
                )}
              </span>

              <span className="text-xs font-bold px-3 py-1 rounded-full bg-white text-blue-950 border border-blue-200 shadow-xs">
                Confidence: <strong className="text-blue-700">{result.confidence}%</strong>
              </span>

              {result.threatIntel.targetedBrand && (
                <span className="text-xs font-bold px-3 py-1 rounded-full bg-purple-100 text-purple-900 border border-purple-200">
                  Pretending to be: {result.threatIntel.targetedBrand}
                </span>
              )}
            </div>

            {/* Target URL Display */}
            <div className="space-y-2">
              <div className="p-4 rounded-2xl bg-white border border-blue-100 flex items-center justify-between gap-3 shadow-xs">
                <p className="text-sm sm:text-base font-mono font-bold text-blue-950 break-all select-all">
                  {result.url}
                </p>
                <button
                  onClick={handleCopy}
                  className="p-2 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-800 shrink-0 transition-colors cursor-pointer"
                  title="Copy link"
                >
                  {copiedUrl ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>

              <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-xs text-blue-900/80">
                <span className="flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-blue-600" />
                  <span>Domain: <strong className="text-blue-950 font-mono">{result.domain}</strong></span>
                </span>
                <span>•</span>
                <span className="flex items-center gap-1.5">
                  <Lock className={`h-3.5 w-3.5 ${result.domainInfo.ssl.hasSsl ? 'text-emerald-600' : 'text-rose-600'}`} />
                  <span>Security: <strong className={result.domainInfo.ssl.hasSsl ? 'text-emerald-700' : 'text-rose-700'}>{result.domainInfo.ssl.hasSsl ? 'Encrypted (HTTPS)' : 'Not Secure (HTTP)'}</strong></span>
                </span>
                <span>•</span>
                <span>Age: <strong className="text-blue-950">{result.domainInfo.domainAgeFormatted || 'Unknown / Unverified'}</strong></span>
              </div>
            </div>
          </div>

          {/* Right Threat Score Gauge */}
          <div className="flex items-center gap-4 bg-white p-5 rounded-3xl border border-blue-100 shadow-md shadow-blue-900/5 shrink-0 min-w-[220px]">
            <div className="relative flex items-center justify-center h-20 w-20">
              <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 36 36">
                <path
                  className="text-blue-100"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={
                    isPhish ? 'text-rose-600' : isSuspicious ? 'text-amber-600' : 'text-emerald-600'
                  }
                  strokeDasharray={`${result.riskScore}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute text-center">
                <span className="text-xl font-black text-blue-950">{result.riskScore}</span>
                <span className="text-[10px] block font-mono text-blue-800/70 font-bold">Risk/100</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[11px] uppercase tracking-wider font-extrabold text-blue-900/60 block">
                Safety Rating
              </span>
              <span
                className={`text-base font-extrabold ${
                  isPhish ? 'text-rose-700' : isSuspicious ? 'text-amber-700' : 'text-emerald-700'
                }`}
              >
                {isPhish ? 'Severe Risk' : isSuspicious ? 'Medium Risk' : 'Safe to Visit'}
              </span>
              <p className="text-[11px] text-blue-900/70">
                {isPhish ? 'High likelihood of fraud' : isSuspicious ? 'Unverified domain' : 'Passed security checks'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* MODE 1: SIMPLE / EASY VIEW (For everyday people)                           */}
      {/* ========================================================================= */}
      {viewMode === 'simple' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Action Checklist: "What should you do right now?" */}
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
            <h2 className="text-base font-extrabold text-blue-950 flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-blue-600" />
              <span>What Should You Do Right Now?</span>
            </h2>

            {isPhish ? (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 space-y-2">
                  <div className="flex items-center gap-2 text-rose-700 font-extrabold text-xs">
                    <XCircle className="h-4 w-4 shrink-0 text-rose-600" />
                    <span>1. Do NOT Enter Details</span>
                  </div>
                  <p className="text-xs text-blue-950 leading-relaxed">
                    Never type your password, phone number, card number, or OTP on this website.
                  </p>
                </div>

                <div className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-2">
                  <div className="flex items-center gap-2 text-amber-700 font-extrabold text-xs">
                    <AlertCircle className="h-4 w-4 shrink-0 text-amber-600" />
                    <span>2. Close the Web Page</span>
                  </div>
                  <p className="text-xs text-blue-950 leading-relaxed">
                    Close the tab immediately. If this came from an SMS or email, mark it as spam.
                  </p>
                </div>

                <div className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-2">
                  <div className="flex items-center gap-2 text-blue-700 font-extrabold text-xs">
                    <Lightbulb className="h-4 w-4 shrink-0 text-blue-600" />
                    <span>3. Go Direct to Real Site</span>
                  </div>
                  <p className="text-xs text-blue-950 leading-relaxed">
                    If you need to manage your account, open a fresh tab and type the official name (e.g. paypal.com).
                  </p>
                </div>
              </div>
            ) : isSuspicious ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-2xl bg-amber-50 border border-amber-200 space-y-1.5">
                  <div className="flex items-center gap-2 text-amber-800 font-extrabold text-xs">
                    <AlertCircle className="h-4 w-4 shrink-0 text-amber-600" />
                    <span>Exercise High Caution</span>
                  </div>
                  <p className="text-xs text-blue-950 leading-relaxed">
                    This domain has several unverified attributes. Avoid entering sensitive passwords or payment details.
                  </p>
                </div>
                <div className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-1.5">
                  <div className="flex items-center gap-2 text-blue-800 font-extrabold text-xs">
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
                    <span>Verify with the Sender</span>
                  </div>
                  <p className="text-xs text-blue-950 leading-relaxed">
                    If someone you know sent you this link, ask them directly via phone or another app to confirm they sent it.
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-5 rounded-2xl bg-emerald-50 border border-emerald-200 flex items-start gap-3.5">
                <CheckCircle2 className="h-5 w-5 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-sm font-extrabold text-emerald-950">Safe to Browse</h3>
                  <p className="text-xs text-blue-950 mt-0.5 leading-relaxed">
                    This website matches standard security standards, has valid encryption, and is established with known reputation authorities.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Plain English "Why Was This Flagged?" */}
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
            <h2 className="text-base font-extrabold text-blue-950 flex items-center gap-2">
              <Lightbulb className="h-5 w-5 text-amber-500" />
              <span>Why Did We Rate This Link as {result.threatLevel}?</span>
            </h2>

            {/* AI Summary in simple terms */}
            <div className="p-5 rounded-2xl bg-blue-50/50 border border-blue-100 text-xs sm:text-sm text-blue-950 leading-relaxed">
              {result.xai.summary}
            </div>

            {/* Red Flag Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              {result.xai.primaryRiskFactors.map((factor, idx) => (
                <div key={idx} className="p-4 rounded-2xl bg-rose-50/70 border border-rose-100 flex items-start gap-2.5">
                  <AlertCircle className="h-4 w-4 text-rose-600 shrink-0 mt-0.5" />
                  <span className="text-xs text-rose-950 leading-relaxed font-medium">{factor}</span>
                </div>
              ))}

              {result.xai.positiveSecurityIndicators.map((safeguard, idx) => (
                <div key={idx} className="p-4 rounded-2xl bg-emerald-50/70 border border-emerald-100 flex items-start gap-2.5">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span className="text-xs text-emerald-950 leading-relaxed font-medium">{safeguard}</span>
                </div>
              ))}
            </div>
          </div>

          {/* One-Click Share & Family Warning */}
          <div className="rounded-3xl bg-gradient-to-r from-blue-600 via-blue-700 to-indigo-700 p-6 sm:p-8 text-white flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-xl shadow-blue-600/15">
            <div className="space-y-1">
              <h3 className="text-base font-extrabold flex items-center gap-2">
                <Share2 className="h-5 w-5 text-sky-300" />
                <span>Protect Family and Friends from this Link</span>
              </h3>
              <p className="text-xs text-blue-100 leading-relaxed">
                Copy an easy-to-read safety summary to warn someone before they click.
              </p>
            </div>

            <button
              onClick={handleCopyShareWarning}
              className="px-6 py-3 rounded-2xl bg-white text-blue-950 hover:bg-blue-50 font-extrabold text-xs shadow-lg shadow-blue-950/20 transition-all flex items-center gap-2 shrink-0 cursor-pointer"
            >
              {copiedShareText ? (
                <>
                  <Check className="h-4 w-4 text-emerald-600" />
                  <span className="text-emerald-700">Warning Copied to Clipboard!</span>
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4 text-blue-600" />
                  <span>Copy Shareable Warning</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE 2: CYBER PRO / SVM DEEP DIVE (For security specialists & students)   */}
      {/* ========================================================================= */}
      {viewMode === 'pro' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Sub-Tabs for Pro View */}
          <div className="flex items-center gap-1 border-b border-blue-100 overflow-x-auto no-scrollbar">
            {[
              { id: 'xai', label: 'Explainable AI (XAI)', icon: Sparkles },
              { id: 'features', label: '24 Academic Features', icon: Layers, badge: `${featureList.filter((f) => f.score === -1).length} flagged` },
              { id: 'svm', label: 'SVM Decision Math', icon: Cpu },
              { id: 'whois', label: 'WHOIS, DNS & SSL', icon: Globe },
              { id: 'threats', label: 'Threat Feeds & Blacklists', icon: Radio },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center gap-2 px-4 py-3 border-b-2 text-xs font-bold transition-all whitespace-nowrap cursor-pointer ${
                    isActive
                      ? 'border-blue-600 text-blue-700 bg-blue-50/50'
                      : 'border-transparent text-blue-900/70 hover:text-blue-950 hover:bg-blue-50/30'
                  }`}
                >
                  <Icon className={`h-4 w-4 ${isActive ? 'text-blue-600' : 'text-blue-500'}`} />
                  <span>{tab.label}</span>
                  {tab.badge && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-100 text-blue-900 font-bold">
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Sub-Tab Content 1: Explainable AI */}
          {activeTab === 'xai' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
                <div className="flex items-center justify-between border-b border-blue-100 pb-3">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-xl bg-blue-50 text-blue-600 border border-blue-200">
                      <Sparkles className="h-4 w-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-extrabold text-blue-950">Explainable AI (XAI) Security Verdict</h3>
                      <p className="text-[11px] text-blue-900/70">
                        Natural language interpretation of SVM decision boundaries and threat heuristics
                      </p>
                    </div>
                  </div>

                  {result.xai.generatedByAi && (
                    <span className="text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-800 border border-blue-200">
                      Powered by Gemini 2.5
                    </span>
                  )}
                </div>

                <div className="p-5 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-2">
                  <p className="text-sm text-blue-950 leading-relaxed font-sans font-medium">
                    {result.xai.summary}
                  </p>
                  <p className="text-xs text-blue-900/70 leading-relaxed font-sans">
                    {result.xai.verdictReasoning}
                  </p>
                </div>

                {/* Attack Taxonomy & MITRE ATT&CK */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                  <div className="p-4 rounded-2xl bg-white border border-blue-100 space-y-1.5 shadow-xs">
                    <span className="text-[11px] font-mono font-bold uppercase text-blue-600 block">
                      Identified Attack Vector Type
                    </span>
                    <p className="text-xs font-extrabold text-blue-950">{result.xai.attackVectorType}</p>
                    {result.xai.suspectedBrandImpersonation && (
                      <p className="text-[11px] text-purple-700 font-bold">
                        Target Organization: <strong>{result.xai.suspectedBrandImpersonation}</strong>
                      </p>
                    )}
                  </div>

                  <div className="p-4 rounded-2xl bg-white border border-blue-100 space-y-1.5 shadow-xs">
                    <span className="text-[11px] font-mono font-bold uppercase text-blue-600 block">
                      MITRE ATT&CK Techniques
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {result.xai.tacticsTechniques.map((tac, idx) => (
                        <span key={idx} className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200">
                          {tac}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Actionable SOC Recommendations */}
                <div className="p-5 rounded-2xl bg-white border border-blue-100 space-y-2 shadow-xs">
                  <h4 className="text-xs font-extrabold uppercase tracking-wider text-blue-800 flex items-center gap-1.5">
                    <Award className="h-3.5 w-3.5 text-blue-600" />
                    Actionable SOC Mitigation Recommendations
                  </h4>
                  <ul className="space-y-1.5">
                    {result.xai.actionableRecommendations.map((rec, idx) => (
                      <li key={idx} className="text-xs text-blue-950 flex items-start gap-2">
                        <span className="text-blue-600 font-extrabold">{idx + 1}.</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* SHAP Feature Contribution Chart */}
              <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
                <div className="flex items-center justify-between border-b border-blue-100 pb-3">
                  <div>
                    <h3 className="text-sm font-extrabold text-blue-950">SHAP Feature Impact Waterfall</h3>
                    <p className="text-[11px] text-blue-900/70">
                      Feature directional contribution to SVM decision boundary (Negative = Phishing pull, Positive = Legitimate)
                    </p>
                  </div>
                  <BarChart3 className="h-5 w-5 text-blue-600" />
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={topImpactFeatures} layout="vertical" margin={{ top: 5, right: 20, left: 30, bottom: 5 }}>
                      <XAxis type="number" stroke="#64748b" fontSize={11} domain={[-2.5, 2.5]} />
                      <YAxis type="category" dataKey="name" stroke="#1e3a8a" fontSize={11} width={130} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#ffffff', borderColor: '#bfdbfe', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                        itemStyle={{ color: '#172554', fontSize: '12px', fontWeight: 'bold' }}
                      />
                      <Bar dataKey="impact" radius={[4, 4, 4, 4]}>
                        {topImpactFeatures.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.impact < 0 ? '#ef4444' : '#10b981'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab Content 2: 24 Features */}
          {activeTab === 'features' && (
            <div className="space-y-4 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 rounded-2xl bg-white border border-blue-100 shadow-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  {[
                    { id: 'all', label: 'All 24 Features' },
                    { id: 'url_structure', label: 'URL Structure' },
                    { id: 'domain_ssl', label: 'Domain & SSL' },
                    { id: 'heuristics_content', label: 'Content & Heuristics' },
                    { id: 'threat_reputation', label: 'Threat Feeds' },
                  ].map((cat) => (
                    <button
                      key={cat.id}
                      onClick={() => setFeatureCategoryFilter(cat.id)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-colors cursor-pointer ${
                        featureCategoryFilter === cat.id
                          ? 'bg-blue-600 text-white shadow-xs'
                          : 'text-blue-900/70 hover:text-blue-950 bg-blue-50'
                      }`}
                    >
                      {cat.label}
                    </button>
                  ))}
                </div>

                <input
                  type="text"
                  value={featureSearch}
                  onChange={(e) => setFeatureSearch(e.target.value)}
                  placeholder="Filter features..."
                  className="px-3.5 py-1.5 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600 font-mono"
                />
              </div>

              <div className="overflow-hidden rounded-3xl bg-white border border-blue-100 shadow-xl shadow-blue-900/5">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-blue-50/80 border-b border-blue-100 font-mono text-blue-900 uppercase text-[10px]">
                      <tr>
                        <th className="px-4 py-3.5">Academic Feature</th>
                        <th className="px-4 py-3.5">Category</th>
                        <th className="px-4 py-3.5">Extracted Value</th>
                        <th className="px-4 py-3.5">SVM Score</th>
                        <th className="px-4 py-3.5">SVM Weight ($w_i$)</th>
                        <th className="px-4 py-3.5">Inspection Rationale</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-blue-50">
                      {filteredFeatures.map((feat) => (
                        <tr key={feat.id} className="hover:bg-blue-50/40 transition-colors">
                          <td className="px-4 py-3 font-bold text-blue-950">{feat.name}</td>
                          <td className="px-4 py-3">
                            <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-50 text-blue-800 border border-blue-200">
                              {feat.category.replace('_', ' ')}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-blue-900">{String(feat.value)}</td>
                          <td className="px-4 py-3">
                            <span
                              className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded-full ${
                                feat.score === -1
                                  ? 'bg-rose-100 text-rose-800 border border-rose-200'
                                  : feat.score === 0
                                  ? 'bg-amber-100 text-amber-800 border border-amber-200'
                                  : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                              }`}
                            >
                              {feat.score === -1 ? '-1 (Phishing)' : feat.score === 0 ? '0 (Suspicious)' : '+1 (Legit)'}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-blue-900 font-bold">{feat.weight.toFixed(2)}</td>
                          <td className="px-4 py-3 text-blue-900/80 max-w-xs leading-relaxed">{feat.rationale}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab Content 3: SVM Math */}
          {activeTab === 'svm' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-5 rounded-2xl bg-white border border-blue-100 space-y-1 shadow-xs">
                  <span className="text-[10px] font-mono font-bold uppercase text-blue-600">Hyperplane Decision Value f(x)</span>
                  <div className="text-2xl font-mono font-black text-blue-950">{result.svm.decisionValue}</div>
                  <p className="text-[11px] text-blue-900/70">
                    {result.svm.decisionValue < 0 ? 'Negative region (Phishing subspace)' : 'Positive region (Legitimate subspace)'}
                  </p>
                </div>

                <div className="p-5 rounded-2xl bg-white border border-blue-100 space-y-1 shadow-xs">
                  <span className="text-[10px] font-mono font-bold uppercase text-blue-600">Geometric Margin Distance</span>
                  <div className="text-2xl font-mono font-black text-indigo-900">{result.svm.hyperplaneDistance}</div>
                  <p className="text-[11px] text-blue-900/70">Normalized distance d = |f(x)| / ||w||</p>
                </div>

                <div className="p-5 rounded-2xl bg-white border border-blue-100 space-y-1 shadow-xs">
                  <span className="text-[10px] font-mono font-bold uppercase text-blue-600">Kernel Algorithm</span>
                  <div className="text-base font-extrabold text-emerald-800 mt-1">{result.svm.kernelType}</div>
                  <p className="text-[11px] font-mono text-blue-900/70">γ = {result.svm.gamma}, C = {result.svm.cParameter}</p>
                </div>
              </div>

              <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
                <h3 className="text-sm font-extrabold text-blue-950 flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-blue-600" />
                  <span>Support Vector Machine Mathematical Formulation</span>
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-4 rounded-2xl bg-blue-50/60 border border-blue-200 font-mono text-xs space-y-2">
                    <span className="text-blue-800 font-bold block">// Primary SVM Decision Boundary</span>
                    <p className="text-blue-950 font-bold">f(x) = sign( ∑ αᵢ yᵢ K(xᵢ, x) + b )</p>
                    <p className="text-[11px] text-blue-900/70 font-sans">
                      Where αᵢ are Lagrange multipliers for support vectors, yᵢ ∈ {'{-1, +1}'}, and b = -0.42.
                    </p>
                  </div>

                  <div className="p-4 rounded-2xl bg-blue-50/60 border border-blue-200 font-mono text-xs space-y-2">
                    <span className="text-indigo-800 font-bold block">// RBF Gaussian Kernel Function</span>
                    <p className="text-blue-950 font-bold">K(x, z) = exp( -γ ||x - z||² )</p>
                    <p className="text-[11px] text-blue-900/70 font-sans">
                      Evaluates proximity in infinite-dimensional Hilbert feature space.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab Content 4: WHOIS */}
          {activeTab === 'whois' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
                  <h3 className="text-sm font-extrabold text-blue-950 flex items-center gap-2 border-b border-blue-100 pb-3">
                    <Globe className="h-4 w-4 text-blue-600" />
                    <span>WHOIS Registration Records</span>
                  </h3>
                  <dl className="grid grid-cols-2 gap-y-3.5 gap-x-4 text-xs">
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Domain Name</dt>
                      <dd className="font-bold text-blue-950 font-mono">{result.domainInfo.domain}</dd>
                    </div>
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Registrar</dt>
                      <dd className="font-semibold text-blue-950">{result.domainInfo.registrar}</dd>
                    </div>
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Creation Date</dt>
                      <dd className="font-semibold text-blue-950 font-mono">{result.domainInfo.creationDate}</dd>
                    </div>
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Domain Age</dt>
                      <dd className={`font-bold font-mono ${result.domainInfo.domainAgeDays < 180 ? 'text-rose-600' : 'text-emerald-700'}`}>
                        {result.domainInfo.domainAgeFormatted}
                      </dd>
                    </div>
                  </dl>
                </div>

                <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
                  <h3 className="text-sm font-extrabold text-blue-950 flex items-center gap-2 border-b border-blue-100 pb-3">
                    <Lock className="h-4 w-4 text-blue-600" />
                    <span>SSL / TLS Certificate</span>
                  </h3>
                  <dl className="grid grid-cols-2 gap-y-3.5 gap-x-4 text-xs">
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Protocol</dt>
                      <dd className="font-bold text-blue-950 font-mono">{result.domainInfo.ssl.protocol}</dd>
                    </div>
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Certificate Issuer</dt>
                      <dd className="font-semibold text-blue-950">{result.domainInfo.ssl.issuer}</dd>
                    </div>
                    <div>
                      <dt className="text-blue-900/60 font-mono text-[11px]">Validity Status</dt>
                      <dd className={`font-bold ${result.domainInfo.ssl.valid ? 'text-emerald-700' : 'text-rose-600'}`}>
                        {result.domainInfo.ssl.valid ? 'Valid & Verified' : 'Invalid / Expired / None'}
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab Content 5: Threat Feeds */}
          {activeTab === 'threats' && (
            <div className="space-y-4 animate-in fade-in duration-200">
              <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
                <div className="flex items-center justify-between border-b border-blue-100 pb-3">
                  <div>
                    <h3 className="text-sm font-extrabold text-blue-950">Global Threat Intelligence Telemetry</h3>
                    <p className="text-[11px] text-blue-900/70">
                      Cross-referenced against verified reputation feeds (Google Safe Browsing, VirusTotal)
                    </p>
                  </div>
                  <span
                    className={`text-xs font-mono font-bold px-3 py-1 rounded-full ${
                      result.threatIntel.isBlacklisted
                        ? 'bg-rose-100 text-rose-800 border border-rose-200'
                        : result.threatIntel.overallReputation === 'Clean'
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        : 'bg-slate-100 text-slate-800 border border-slate-200'
                    }`}
                  >
                    {result.threatIntel.overallReputation}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
                  {result.threatIntel.sources.map((src, idx) => (
                    <div key={idx} className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-blue-950">{src.name}</span>
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-white text-blue-800 border border-blue-200">
                          {src.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-blue-900/70">{src.category}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Export Security Report Modal */}
      {showExportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md animate-in fade-in duration-200">
          <div className="relative w-full max-w-xl p-6 sm:p-8 rounded-3xl bg-white border border-blue-200 shadow-2xl space-y-6">
            <button
              onClick={() => setShowExportModal(false)}
              className="absolute top-5 right-5 p-1.5 rounded-full text-blue-400 hover:text-blue-950 hover:bg-blue-50 transition-colors cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="space-y-1">
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200 text-[10px] font-mono font-bold">
                <FileText className="h-3 w-3" />
                <span>Forensic Intelligence Export</span>
              </div>
              <h3 className="text-xl font-extrabold text-blue-950">Export Threat Assessment</h3>
              <p className="text-xs text-blue-900/70">
                Download or copy forensic telemetry for <strong className="text-blue-950">{result.domain}</strong>
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <button
                onClick={handlePrint}
                className="p-4 rounded-2xl bg-blue-50/50 hover:bg-blue-50 border border-blue-200 text-left space-y-2 transition-all group cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded-xl bg-blue-600 text-white group-hover:bg-blue-700 transition-colors shadow-xs">
                    <Printer className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono font-bold text-blue-700">Print / PDF</span>
                </div>
                <div>
                  <h4 className="text-xs font-extrabold text-blue-950">Executive PDF Report</h4>
                  <p className="text-[11px] text-blue-900/70">Formatted executive summary for stakeholder briefing</p>
                </div>
              </button>

              <button
                onClick={downloadJson}
                className="p-4 rounded-2xl bg-blue-50/50 hover:bg-blue-50 border border-blue-200 text-left space-y-2 transition-all group cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded-xl bg-indigo-600 text-white group-hover:bg-indigo-700 transition-colors shadow-xs">
                    <Download className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono font-bold text-indigo-700">.JSON</span>
                </div>
                <div>
                  <h4 className="text-xs font-extrabold text-blue-950">Full JSON Telemetry</h4>
                  <p className="text-[11px] text-blue-900/70">Raw features, SVM weights, WHOIS, and Gemini XAI</p>
                </div>
              </button>

              <button
                onClick={downloadCsv}
                className="p-4 rounded-2xl bg-blue-50/50 hover:bg-blue-50 border border-blue-200 text-left space-y-2 transition-all group cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded-xl bg-emerald-600 text-white group-hover:bg-emerald-700 transition-colors shadow-xs">
                    <Download className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono font-bold text-emerald-700">.CSV</span>
                </div>
                <div>
                  <h4 className="text-xs font-extrabold text-blue-950">24 Feature Vectors (CSV)</h4>
                  <p className="text-[11px] text-blue-900/70">Matrix of URL feature values, weights, and impacts</p>
                </div>
              </button>

              <button
                onClick={copyMarkdown}
                className="p-4 rounded-2xl bg-blue-50/50 hover:bg-blue-50 border border-blue-200 text-left space-y-2 transition-all group cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded-xl bg-purple-600 text-white group-hover:bg-purple-700 transition-colors shadow-xs">
                    {copiedExportFormat === 'md' ? <Check className="h-4 w-4 text-emerald-300" /> : <Copy className="h-4 w-4" />}
                  </div>
                  <span className="text-[10px] font-mono font-bold text-purple-700">
                    {copiedExportFormat === 'md' ? 'Copied!' : 'Markdown'}
                  </span>
                </div>
                <div>
                  <h4 className="text-xs font-extrabold text-blue-950">SOC Incident Ticket</h4>
                  <p className="text-[11px] text-blue-900/70">Copy formatted markdown for JIRA, Slack, or GitHub</p>
                </div>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
