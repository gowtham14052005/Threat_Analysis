import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  Globe,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ArrowLeft,
  Share2,
  Info,
  ExternalLink,
  Cpu,
  Terminal,
  Activity,
  Layers,
  Fingerprint,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { ScanResult, ExtractedFeatureItem } from '../types';
import { cyberAudio } from '../lib/cyber-sound';

interface SecureScoreResultProps {
  result: ScanResult;
  onNewScan: () => void;
}

export const SecureScoreResult: React.FC<SecureScoreResultProps> = ({
  result,
  onNewScan,
}) => {
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);
  const [showDeepDiagnostics, setShowDeepDiagnostics] = useState(false);

  // Secure score is 100 - riskScore (0 = completely dangerous/non-existent, 100 = completely secure)
  const secureScore = Math.max(0, Math.min(100, Math.round(100 - result.riskScore)));

  const isNonExistent =
    result.verdict === 'NOT_FOUND' ||
    result.threatLevel === 'NOT_FOUND' ||
    result.domainInfo?.verificationStatus === 'Non-Existent Domain' ||
    result.websiteStatus?.status === 'NON_EXISTENT';

  const isParked =
    result.verdict === 'PARKED' ||
    result.threatLevel === 'PARKED' ||
    result.domainInfo?.isParked ||
    result.domainInfo?.verificationStatus === 'Parked / Inactive Domain' ||
    result.websiteStatus?.status === 'PARKED';

  const isUnreachable =
    result.verdict === 'INACTIVE' ||
    result.threatLevel === 'INACTIVE' ||
    result.websiteStatus?.status === 'UNREACHABLE';

  const isPhish =
    !isNonExistent &&
    !isParked &&
    (result.isPhishing ||
      result.verdict === 'PHISHING' ||
      result.threatLevel === 'PHISHING' ||
      secureScore < 40);

  const isSuspicious =
    !isNonExistent &&
    !isParked &&
    !isUnreachable &&
    !isPhish &&
    (result.verdict === 'SUSPICIOUS' ||
      result.threatLevel === 'SUSPICIOUS' ||
      secureScore < 75);

  const isSecure = !isNonExistent && !isParked && !isUnreachable && !isPhish && !isSuspicious;

  // Trigger cyber audio cue once upon result display
  useEffect(() => {
    if (isSecure) {
      cyberAudio.playSafeHarmonic();
    } else if (isPhish) {
      cyberAudio.playThreatAlert();
    } else {
      cyberAudio.playWarningChirp();
    }
  }, [result.url]);

  const handleCopyUrl = () => {
    cyberAudio.playBlip(1200);
    navigator.clipboard.writeText(result.url);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const handleCopySummary = () => {
    cyberAudio.playBlip(1200);
    let verdictLabel = 'VERIFIED SECURE';
    if (isNonExistent) verdictLabel = 'DOMAIN DOES NOT EXIST (NXDOMAIN)';
    else if (isParked) verdictLabel = 'PARKED DOMAIN (NO ACTIVE WEBSITE)';
    else if (isUnreachable) verdictLabel = 'UNREACHABLE HOST';
    else if (isPhish) verdictLabel = 'DANGEROUS PHISHING SCAM';
    else if (isSuspicious) verdictLabel = 'SUSPICIOUS LINK';

    const text = `[CYBER THREAT ASSESSMENT]\nTarget: ${result.url}\nSecure Score: ${secureScore}/100\nVerdict: ${verdictLabel}\nThreat Level: ${result.threatLevel}\n\nSummary:\n${
      result.xai?.summary || 'Link analysis completed.'
    }\n\nRecommendation:\n${
      isSecure
        ? 'Safe to visit. Verified legitimate infrastructure.'
        : isNonExistent
        ? 'Domain does not exist on the internet. Do not trust messages containing this link.'
        : isParked
        ? 'No active website exists here. Avoid clicking ad parking links.'
        : 'Do NOT open or enter sensitive credentials on this link.'
    }`;
    navigator.clipboard.writeText(text);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  // Color scheme & Cyber HUD styling based on threat status
  const cyberConfig = isNonExistent
    ? {
        ringColor: '#64748b',
        glowColor: 'rgba(100, 116, 139, 0.35)',
        textAccent: 'text-slate-400',
        badgeBg: 'bg-slate-800 text-slate-200 border-slate-700',
        defcon: 'DEFCON STATUS: INVALID TARGET',
        statusTitle: 'Domain Does Not Exist (NXDOMAIN)',
        statusDesc: 'No active DNS records, nameservers, or host found on the internet.',
        icon: XCircle,
      }
    : isParked
    ? {
        ringColor: '#f59e0b',
        glowColor: 'rgba(245, 158, 11, 0.4)',
        textAccent: 'text-amber-500',
        badgeBg: 'bg-amber-950/80 text-amber-300 border-amber-500/50',
        defcon: 'DEFCON 3: DORMANT ASSET',
        statusTitle: 'Parked Domain (No Active Website)',
        statusDesc: 'Domain is held for sale or advertising placeholder. No legitimate web application operates here.',
        icon: AlertTriangle,
      }
    : isUnreachable
    ? {
        ringColor: '#f59e0b',
        glowColor: 'rgba(245, 158, 11, 0.4)',
        textAccent: 'text-amber-500',
        badgeBg: 'bg-amber-950/80 text-amber-300 border-amber-500/50',
        defcon: 'DEFCON 3: HOST OFFLINE',
        statusTitle: 'Server Unreachable / Inactive',
        statusDesc: 'The domain has valid DNS records, but the web server failed to respond.',
        icon: AlertTriangle,
      }
    : isSecure
    ? {
        ringColor: '#00ff9d',
        glowColor: 'rgba(0, 255, 157, 0.45)',
        textAccent: 'text-emerald-500 dark:text-[#00ff9d]',
        badgeBg: 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50',
        defcon: 'DEFCON 5: CLEAR // SECURE',
        statusTitle: 'Verified Authentic & Secure',
        statusDesc: 'Passes all 24 heuristic dimensions with verified authority records.',
        icon: ShieldCheck,
      }
    : isSuspicious
    ? {
        ringColor: '#f59e0b',
        glowColor: 'rgba(245, 158, 11, 0.4)',
        textAccent: 'text-amber-500',
        badgeBg: 'bg-amber-950/80 text-amber-300 border-amber-500/50',
        defcon: 'DEFCON 2: ELEVATED RISK',
        statusTitle: 'Caution: Suspicious Link',
        statusDesc: 'Domain contains structural anomalies or unverified registration.',
        icon: AlertTriangle,
      }
    : {
        ringColor: '#f43f5e',
        glowColor: 'rgba(244, 63, 94, 0.5)',
        textAccent: 'text-rose-500',
        badgeBg: 'bg-rose-950/80 text-rose-300 border-rose-500/50',
        defcon: 'DEFCON 1: CRITICAL PHISHING SCAM',
        statusTitle: 'Severe Phishing / Deception Detected',
        statusDesc: 'High-confidence credential harvesting lure, brand spoof, or malicious redirect.',
        icon: ShieldAlert,
      };

  const StatusIcon = cyberConfig.icon;
  const hasValidSsl = Boolean(result.domainInfo?.ssl?.hasSsl) && !isNonExistent;
  const domainAge = result.domainInfo?.domainAgeFormatted || 'Unrated';
  const targetedBrand = result.threatIntel?.targetedBrand || result.xai?.suspectedBrandImpersonation;

  // Circular gauge calculations
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (secureScore / 100) * circumference;

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Top Cyber Navigation & Actions */}
      <div className="flex items-center justify-between gap-3">
        <button
          id="check-another-url-btn"
          onClick={() => {
            cyberAudio.playBlip(900);
            onNewScan();
          }}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 text-xs font-mono font-bold text-slate-800 dark:text-cyan-300 hover:bg-slate-50 dark:hover:bg-cyan-950/40 shadow-xs transition-colors cursor-pointer"
        >
          <ArrowLeft className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
          <span>&lt; SCAN NEW TARGET</span>
        </button>

        <button
          id="copy-summary-btn"
          onClick={handleCopySummary}
          className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 text-xs font-mono font-bold text-slate-800 dark:text-cyan-300 hover:bg-slate-50 dark:hover:bg-cyan-950/40 shadow-xs transition-colors cursor-pointer"
        >
          {copiedSummary ? (
            <>
              <Check className="h-4 w-4 text-emerald-500" />
              <span className="text-emerald-600 dark:text-emerald-400 font-bold">REPORT COPIED!</span>
            </>
          ) : (
            <>
              <Share2 className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              <span>EXPORT REPORT</span>
            </>
          )}
        </button>
      </div>

      {/* Main Cyber Threat Gauge & Target Identity Hero Card */}
      <div className="cyber-hud-card rounded-3xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/40 p-6 sm:p-8 shadow-xl shadow-cyan-950/10 dark:shadow-cyan-950/30 space-y-6">
        {/* Target URL Header Bar with Monospace Coordinates */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-slate-100 dark:border-slate-800/80">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className="text-cyan-600 dark:text-cyan-400 font-bold">TARGET HOST:</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-[#070e1e] border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 font-semibold truncate max-w-[280px] sm:max-w-md">
                {result.domainInfo?.domain || result.url}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-base sm:text-lg font-mono font-bold text-slate-900 dark:text-white break-all select-all">
                {result.url}
              </span>
              <button
                type="button"
                onClick={handleCopyUrl}
                className="p-1.5 text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors shrink-0 cursor-pointer rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
                title="Copy Target URL"
              >
                {copiedUrl ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
              </button>
            </div>
          </div>

          {/* DEFCON Status Pill */}
          <div className="shrink-0">
            <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-cyber font-black tracking-widest uppercase shadow-xs ${cyberConfig.badgeBg}`}>
              <span className="h-2 w-2 rounded-full bg-current animate-ping" />
              <span>{cyberConfig.defcon}</span>
            </span>
          </div>
        </div>

        {/* Centerpiece: Cyber Holographic Radial Gauge & Assessment */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-8 py-2">
          {/* Left: Holographic Gauge */}
          <div className="flex flex-col items-center text-center shrink-0">
            <div className="relative w-48 h-48 flex items-center justify-center">
              {/* Radial HUD tick markings */}
              <div className="absolute inset-0 rounded-full border border-dashed border-cyan-500/20 animate-spin" style={{ animationDuration: '30s' }} />

              <svg className="w-44 h-44 -rotate-90 transform" viewBox="0 0 160 160">
                {/* Background Ring Track */}
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  className="stroke-slate-100 dark:stroke-slate-800/80"
                  strokeWidth="12"
                  fill="transparent"
                />
                {/* Active Score Glow Ring */}
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  stroke={cyberConfig.ringColor}
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-1000 ease-out"
                  style={{
                    filter: `drop-shadow(0 0 10px ${cyberConfig.glowColor})`,
                  }}
                />
              </svg>

              {/* Central Holographic Score Content */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-4xl sm:text-5xl font-cyber font-black tracking-tight text-slate-900 dark:text-white">
                  {secureScore}
                </span>
                <span className="text-[11px] font-cyber font-bold tracking-widest text-slate-400 uppercase">
                  / 100 SECURE
                </span>
              </div>
            </div>

            <div className="mt-3 flex items-center gap-1.5 text-xs font-mono font-bold text-slate-600 dark:text-slate-400">
              <Activity className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
              <span>CONFIDENCE: {Math.round((result.confidence || 0.95) * 100)}%</span>
            </div>
          </div>

          {/* Right: Threat Verdict & Executive Summary */}
          <div className="flex-1 space-y-3.5 text-left w-full">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <StatusIcon className={`h-6 w-6 ${cyberConfig.textAccent}`} />
                <h2 className="text-xl sm:text-2xl font-cyber font-black tracking-wide text-slate-900 dark:text-white uppercase">
                  {cyberConfig.statusTitle}
                </h2>
              </div>
              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-tech">
                {cyberConfig.statusDesc}
              </p>
            </div>

            {/* AI / Heuristic Analysis Summary */}
            <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#070e1e] border border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed font-tech space-y-2">
              <p>
                {result.xai?.summary ||
                  (isNonExistent
                    ? 'This domain does not exist in global internet DNS (NXDOMAIN). No legitimate server or service operates here.'
                    : isParked
                    ? 'This is a parked domain held for sale with no active website application or legitimate organization.'
                    : isSecure
                    ? 'Verified authoritative domain with standard cryptographic certificates and clean heuristic vector profiles.'
                    : 'Threat indicators detected. Exercise severe caution before interacting with this web asset.')}
              </p>

              {targetedBrand && (
                <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 text-xs font-mono font-bold">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>SPOOFED ENTITY: {targetedBrand.toUpperCase()}</span>
                </div>
              )}
            </div>

            {/* Action Directives */}
            <div className={`p-3.5 rounded-2xl border text-xs font-mono ${
              isSecure
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
                : isNonExistent
                ? 'bg-slate-500/10 border-slate-500/30 text-slate-700 dark:text-slate-300'
                : isParked
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-800 dark:text-amber-300'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-800 dark:text-rose-300'
            }`}>
              <span className="font-black uppercase mr-2">[RECOMMENDED ACTION]:</span>
              <span className="font-tech text-xs">
                {isSecure
                  ? 'Safe to proceed. Target passes encryption and authoritative domain checks.'
                  : isNonExistent
                  ? 'Do NOT trust messages or links referencing this domain. NXDOMAIN links are frequently used in email sender fraud.'
                  : isParked
                  ? 'Avoid clicking parking advertisements or redirected forms. No web application exists here.'
                  : 'DO NOT enter credentials, login details, or financial accounts on this destination.'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 4 Cyber Security Telemetry Pillars */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Pillar 1: Connection Security */}
        <div className="cyber-hud-card p-4 rounded-2xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 shadow-xs space-y-2">
          <div className="flex items-center justify-between text-xs font-cyber text-slate-400">
            <span className="font-bold uppercase tracking-wider">TRANSPORT</span>
            {isNonExistent ? (
              <XCircle className="h-4 w-4 text-slate-400" />
            ) : isParked ? (
              <AlertTriangle className="h-4 w-4 text-amber-500" />
            ) : hasValidSsl ? (
              <Lock className="h-4 w-4 text-emerald-500" />
            ) : (
              <Unlock className="h-4 w-4 text-rose-500" />
            )}
          </div>
          <div className="text-sm font-cyber font-black text-slate-900 dark:text-white tracking-wide">
            {isNonExistent
              ? 'NO HOST'
              : isParked
              ? 'PARKED PAGE'
              : isUnreachable
              ? 'OFFLINE'
              : hasValidSsl
              ? 'ENCRYPTED (TLS)'
              : 'PLAINTEXT (INSECURE)'}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-tech">
            {isNonExistent
              ? 'Domain does not resolve to an active server IP.'
              : isParked
              ? 'Parked placeholder page without verified application.'
              : hasValidSsl
              ? 'Cryptographic handshake and certificate verified.'
              : 'Data in transit is unencrypted and interceptable.'}
          </p>
        </div>

        {/* Pillar 2: Domain Status & Age */}
        <div className="cyber-hud-card p-4 rounded-2xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 shadow-xs space-y-2">
          <div className="flex items-center justify-between text-xs font-cyber text-slate-400">
            <span className="font-bold uppercase tracking-wider">DNS & AGE</span>
            {isNonExistent ? (
              <XCircle className="h-4 w-4 text-rose-500" />
            ) : isParked ? (
              <AlertTriangle className="h-4 w-4 text-amber-500" />
            ) : result.domainInfo?.isVerifiedDomain ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            ) : (
              <Info className="h-4 w-4 text-amber-500" />
            )}
          </div>
          <div className="text-sm font-cyber font-black text-slate-900 dark:text-white tracking-wide">
            {isNonExistent
              ? 'NXDOMAIN'
              : isParked
              ? 'PARKED ASSET'
              : result.domainInfo?.isVerifiedDomain
              ? 'ESTABLISHED CORP'
              : domainAge}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-tech">
            {isNonExistent
              ? 'Non-existent internet domain name.'
              : isParked
              ? 'Held for sale or advertising redirects.'
              : result.domainInfo?.isVerifiedDomain
              ? 'Authoritative enterprise registration.'
              : 'Domain lacks verified organization history.'}
          </p>
        </div>

        {/* Pillar 3: Identity & Brand Spoof */}
        <div className="cyber-hud-card p-4 rounded-2xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 shadow-xs space-y-2">
          <div className="flex items-center justify-between text-xs font-cyber text-slate-400">
            <span className="font-bold uppercase tracking-wider">BRAND INTEGRITY</span>
            {isNonExistent ? (
              <XCircle className="h-4 w-4 text-slate-400" />
            ) : isParked ? (
              <AlertTriangle className="h-4 w-4 text-amber-500" />
            ) : targetedBrand ? (
              <XCircle className="h-4 w-4 text-rose-500" />
            ) : (
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            )}
          </div>
          <div className="text-sm font-cyber font-black text-slate-900 dark:text-white tracking-wide">
            {isNonExistent
              ? 'NO ENTITY'
              : isParked
              ? 'NO APP'
              : targetedBrand
              ? 'SPOOFED BRAND'
              : 'AUTHENTIC'}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-tech">
            {isNonExistent
              ? 'No brand or organization operates here.'
              : isParked
              ? 'Domain parking placeholder without service.'
              : targetedBrand
              ? `Attempting to imitate ${targetedBrand}.`
              : 'No deceptive trademark imitation detected.'}
          </p>
        </div>

        {/* Pillar 4: Syntax & Obfuscation */}
        <div className="cyber-hud-card p-4 rounded-2xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 shadow-xs space-y-2">
          <div className="flex items-center justify-between text-xs font-cyber text-slate-400">
            <span className="font-bold uppercase tracking-wider">URL SYNTAX</span>
            {isPhish ? (
              <XCircle className="h-4 w-4 text-rose-500" />
            ) : (
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            )}
          </div>
          <div className="text-sm font-cyber font-black text-slate-900 dark:text-white tracking-wide">
            {isPhish ? 'ANOMALOUS' : 'CLEAN STRUCTURE'}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-tech">
            {isPhish
              ? 'Contains suspicious redirects, homoglyphs, or tokens.'
              : 'Standard path and canonical structure without evasion.'}
          </p>
        </div>
      </div>

      {/* Cyber Deep Diagnostics & Attack Surface Accordion */}
      <div className="cyber-hud-card rounded-3xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/30 overflow-hidden shadow-sm transition-all">
        <button
          type="button"
          onClick={() => {
            cyberAudio.playBlip(1100);
            setShowDeepDiagnostics(!showDeepDiagnostics);
          }}
          className="w-full px-6 py-4 flex items-center justify-between text-left text-xs font-cyber font-bold text-slate-800 dark:text-cyan-300 hover:bg-slate-50 dark:hover:bg-cyan-950/20 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <Cpu className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
            <span className="uppercase tracking-wider">
              DEEP TELEMETRY & ATTACK SURFACE INSPECTOR ({Object.keys(result.features || {}).length} VECTORS)
            </span>
          </div>
          <div className="flex items-center gap-2 font-mono">
            <span className="text-[11px] text-slate-400 font-normal">
              {showDeepDiagnostics ? 'COLLAPSE' : 'EXPAND VECTORS'}
            </span>
            {showDeepDiagnostics ? (
              <ChevronUp className="h-4 w-4 text-cyan-500" />
            ) : (
              <ChevronDown className="h-4 w-4 text-cyan-500" />
            )}
          </div>
        </button>

        {showDeepDiagnostics && (
          <div className="px-6 pb-6 pt-2 border-t border-slate-100 dark:border-slate-800/80 space-y-5 animate-in fade-in">
            {/* Host & IP Telemetry Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#070e1e] border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase">IP ADDRESS RESOLUTION</span>
                <div className="font-bold text-slate-800 dark:text-slate-200">
                  {result.domainInfo?.ipAddress || (isNonExistent ? 'NXDOMAIN (0.0.0.0)' : 'Resolved')}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#070e1e] border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase">SVM HYPERPLANE DECISION</span>
                <div className="font-bold text-cyan-600 dark:text-cyan-400">
                  {typeof result.svmMetrics?.decisionValue === 'number'
                    ? `w·x + b = ${result.svmMetrics.decisionValue.toFixed(3)}`
                    : 'Evaluated'}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#070e1e] border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase">THREAT INTELLIGENCE (VT/GSB)</span>
                <div className="font-bold text-slate-800 dark:text-slate-200">
                  {result.threatIntel?.virusTotal?.status || 'Active Feeds'}
                </div>
              </div>
            </div>

            {/* Feature Vector Table */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pb-1">
                <span>EXTRACTED HEURISTIC VECTOR</span>
                <span>STATE // CLASSIFICATION</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-72 overflow-y-auto pr-1">
                {(Object.entries(result.features || {}) as [string, ExtractedFeatureItem][]).map(([key, item]) => {
                  const isSafe = item.score === 1;
                  const isNeutral = item.score === 0;
                  return (
                    <div
                      key={key}
                      className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-[#070e1e] border border-slate-200 dark:border-slate-800/80 text-xs font-mono"
                    >
                      <span className="text-slate-700 dark:text-slate-300 truncate max-w-[200px]" title={item.name}>
                        {item.name}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-black uppercase ${
                          isSafe
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                            : isNeutral
                            ? 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/30'
                            : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                        }`}
                      >
                        {isSafe ? 'LEGITIMATE (+1)' : isNeutral ? 'NEUTRAL (0)' : 'MALICIOUS (-1)'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
