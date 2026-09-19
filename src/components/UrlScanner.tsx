import React, { useState, useEffect } from 'react';
import {
  Globe,
  ArrowRight,
  ShieldCheck,
  AlertCircle,
  Copy,
  Check,
  X,
  Crosshair,
  Radio,
  Cpu,
  Terminal,
  Zap,
} from 'lucide-react';
import { cyberAudio } from '../lib/cyber-sound';

interface UrlScannerProps {
  onScan: (url: string) => void;
  isScanning: boolean;
  initialUrl?: string;
}

const CYBER_TARGET_SAMPLES = [
  {
    tag: 'VERIFIED',
    label: 'Google Security',
    url: 'https://safety.google/authentication-security/',
    color: 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400 bg-emerald-500/10',
  },
  {
    tag: 'PHISHING',
    label: 'PayPal Credential Lure',
    url: 'http://paypa1-security-verification.xyz/login/verify-identity.php?account=suspended',
    color: 'border-rose-500/40 text-rose-600 dark:text-rose-400 bg-rose-500/10',
  },
  {
    tag: 'SMISHING',
    label: 'USPS Delivery Spoof',
    url: 'http://usps-tracking-parcel-update24.top/claim-redelivery?id=99281',
    color: 'border-rose-500/40 text-rose-600 dark:text-rose-400 bg-rose-500/10',
  },
  {
    tag: 'PARKED',
    label: 'Inactive yiut.com',
    url: 'https://yiut.com',
    color: 'border-amber-500/40 text-amber-600 dark:text-amber-400 bg-amber-500/10',
  },
];

const SCAN_TELEMETRY_STEPS = [
  'PROBING GLOBAL DNS A/AAAA RECORDS & NXDOMAIN CHECK...',
  'TESTING HTTP/HTTPS REACHABILITY & PARKING SIGNATURES...',
  'EXTRACTING 24-DIMENSIONAL ACADEMIC SVM URL FEATURES...',
  'QUERYING LIVE THREAT FEEDS (VIRUSTOTAL & GOOGLE SAFE BROWSING)...',
  'COMPUTING SVM HYPERPLANE DECISION BOUNDARY f(x) = w·x + b...',
  'FINALIZING SECURE SCORE & EXPLAINABLE THREAT MATRIX...',
];

export const UrlScanner: React.FC<UrlScannerProps> = ({
  onScan,
  isScanning,
  initialUrl = '',
}) => {
  const [inputUrl, setInputUrl] = useState(initialUrl);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [pasteSuccess, setPasteSuccess] = useState<boolean>(false);
  const [telemetryIndex, setTelemetryIndex] = useState(0);

  // Cycling scanning telemetry text during scan
  useEffect(() => {
    if (!isScanning) {
      setTelemetryIndex(0);
      return;
    }

    const interval = setInterval(() => {
      setTelemetryIndex((prev) => (prev + 1) % SCAN_TELEMETRY_STEPS.length);
      cyberAudio.playScanPulse();
    }, 650);

    return () => clearInterval(interval);
  }, [isScanning]);

  const handleSubmit = (targetUrl?: string) => {
    let urlToTest = (targetUrl || inputUrl).trim();
    if (!urlToTest) {
      setErrorMsg('TARGET ACQUISITION FAILED: Enter or paste a website URL to inspect.');
      cyberAudio.playThreatAlert();
      return;
    }

    // Auto-prepend https:// if missing for convenience
    if (!urlToTest.startsWith('http://') && !urlToTest.startsWith('https://')) {
      urlToTest = 'https://' + urlToTest;
      setInputUrl(urlToTest);
    }

    setErrorMsg(null);
    cyberAudio.playScanPulse();
    onScan(urlToTest);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInputUrl(text.trim());
        setPasteSuccess(true);
        setErrorMsg(null);
        cyberAudio.playBlip(1300);
        setTimeout(() => setPasteSuccess(false), 2000);
      }
    } catch {
      // Clipboard fallback
    }
  };

  const handleClear = () => {
    setInputUrl('');
    setErrorMsg(null);
    cyberAudio.playBlip(700);
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Cyber Command Title & Telemetry Header */}
      <div className="text-center space-y-3">
        {/* Top Tactical Chip */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-50 dark:bg-cyan-950/70 border border-cyan-400 dark:border-cyan-500/40 text-[11px] font-cyber font-bold text-cyan-800 dark:text-cyan-300 shadow-sm">
          <Terminal className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
          <span>CYBER-DEFENSE RADAR // SVM-RBF ENGINE v4.2</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-cyber font-black text-slate-900 dark:text-white tracking-wide uppercase">
          URL THREAT & <span className="bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-400 bg-clip-text text-transparent neon-glow-cyan">SAFETY RADAR</span>
        </h1>

        <p className="text-sm sm:text-base font-tech text-slate-600 dark:text-slate-300 max-w-xl mx-auto leading-relaxed">
          Inspect any link to calculate its real-time <strong className="text-cyan-600 dark:text-cyan-400 font-mono">SECURE SCORE (0–100)</strong>, detect spoofed brands, and identify inactive or parked domains.
        </p>
      </div>

      {/* Main Tactical Scanner Card */}
      <div className="cyber-hud-card cyber-box-glow rounded-3xl bg-white dark:bg-[#0b1329] border border-slate-200 dark:border-cyan-500/40 p-5 sm:p-7 shadow-xl shadow-cyan-950/5 dark:shadow-cyan-950/30 space-y-5 transition-all">
        {/* Card Header Status Bar */}
        <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3 text-[11px] font-tech text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-2">
            <Crosshair className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
            <span className="font-cyber font-bold tracking-wider text-slate-700 dark:text-slate-200 uppercase">Target Acquisition HUD</span>
          </div>
          <div className="flex items-center gap-3 font-mono">
            <span className="hidden sm:inline text-cyan-600 dark:text-cyan-400">24 VECTOR DIMENSIONS</span>
            <span className="hidden sm:inline text-slate-300 dark:text-slate-700">|</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-bold">● SENSORS ONLINE</span>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSubmit();
          }}
          className="space-y-3"
        >
          {/* Main Input Control Bar */}
          <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <div className="relative flex-1 group">
              {/* Tactical Monospace Prefix */}
              <div className="absolute inset-y-0 left-0 pl-3.5 sm:pl-4 flex items-center pointer-events-none text-cyan-600 dark:text-cyan-400">
                <span className="font-mono text-xs font-black tracking-tighter opacity-80 select-none mr-1">
                  TARGET &gt;
                </span>
              </div>

              <input
                id="url-input-field"
                type="text"
                value={inputUrl}
                onChange={(e) => {
                  setInputUrl(e.target.value);
                  if (errorMsg) setErrorMsg(null);
                }}
                placeholder="Paste URL (e.g., https://example.com, payment link, or SMS link)"
                className="w-full pl-22 sm:pl-24 pr-24 py-4 rounded-2xl bg-slate-50 dark:bg-[#070e1e] border border-slate-200 dark:border-cyan-500/40 text-slate-900 dark:text-slate-100 placeholder-slate-400 text-sm sm:text-base font-mono focus:outline-none focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/20 transition-all"
                disabled={isScanning}
                autoFocus
              />

              {/* Laser Scan Sweep Beam inside Input during Scan */}
              {isScanning && (
                <div className="absolute inset-x-0 bottom-0 h-0.5 overflow-hidden rounded-b-2xl">
                  <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-cyber-scan" />
                </div>
              )}

              {/* Action Buttons inside Input */}
              <div className="absolute inset-y-0 right-0 pr-2.5 flex items-center gap-1.5">
                {inputUrl && (
                  <button
                    type="button"
                    onClick={handleClear}
                    className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer rounded-lg hover:bg-slate-200/50 dark:hover:bg-slate-800"
                    title="Clear target"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={handlePaste}
                  className="px-2.5 py-1.5 rounded-xl bg-slate-200/80 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-xs font-mono font-bold text-slate-700 dark:text-slate-200 transition-all flex items-center gap-1 cursor-pointer border border-slate-300/60 dark:border-slate-700"
                  title="Paste from clipboard"
                >
                  {pasteSuccess ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-500" />
                      <span className="text-emerald-600 dark:text-emerald-400 font-bold">PASTED</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3 text-cyan-600 dark:text-cyan-400" />
                      <span>PASTE</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Tactical Execute Button */}
            <button
              id="analyze-url-btn"
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="relative flex items-center justify-center gap-2.5 px-8 py-4 rounded-2xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:via-blue-500 hover:to-indigo-500 text-white font-cyber font-black text-xs sm:text-sm tracking-widest uppercase shadow-lg shadow-cyan-600/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shrink-0 border border-cyan-400/40 overflow-hidden group hover:scale-[1.01]"
            >
              {isScanning ? (
                <>
                  <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  <span>ANALYZING...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="h-4 w-4 text-cyan-200 group-hover:scale-110 transition-transform" />
                  <span>ENGAGE SCAN</span>
                  <ArrowRight className="h-4 w-4 text-cyan-200 group-hover:translate-x-0.5 transition-transform" />
                </>
              )}
            </button>
          </div>

          {/* Error Message HUD Banner */}
          {errorMsg && (
            <div className="flex items-center gap-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/40 text-rose-600 dark:text-rose-400 text-xs font-mono font-semibold animate-in fade-in">
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}
        </form>

        {/* Live Cyber Scanning Telemetry Bar */}
        {isScanning && (
          <div className="pt-2 space-y-2.5 animate-in fade-in duration-200">
            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400">
                <Radio className="h-3.5 w-3.5 animate-pulse" />
                <span className="font-tech font-bold tracking-tight">{SCAN_TELEMETRY_STEPS[telemetryIndex]}</span>
              </div>
              <span className="text-slate-400 font-bold hidden sm:inline">CYCLE {telemetryIndex + 1}/{SCAN_TELEMETRY_STEPS.length}</span>
            </div>
            <div className="h-2 w-full bg-slate-100 dark:bg-[#070e1e] rounded-full overflow-hidden border border-slate-200 dark:border-cyan-500/30 p-0.5">
              <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-400 rounded-full animate-cyber-scan w-full" />
            </div>
          </div>
        )}

        {/* 1-Click Cyber Target Presets */}
        <div className="pt-2 border-t border-slate-100 dark:border-slate-800/80">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-500 dark:text-slate-400 font-cyber text-[11px] font-bold flex items-center gap-1 mr-1">
              <Zap className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
              <span>TARGET PRESETS:</span>
            </span>
            {CYBER_TARGET_SAMPLES.map((sample, idx) => (
              <button
                key={idx}
                id={`sample-url-${idx}`}
                type="button"
                disabled={isScanning}
                onClick={() => {
                  cyberAudio.playBlip(1000);
                  setInputUrl(sample.url);
                  handleSubmit(sample.url);
                }}
                className={`px-3 py-1.5 rounded-xl border text-xs font-tech font-bold transition-all cursor-pointer flex items-center gap-1.5 hover:scale-[1.03] ${sample.color}`}
              >
                <span className="text-[10px] font-mono font-black uppercase opacity-85">[{sample.tag}]</span>
                <span>{sample.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
