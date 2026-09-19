import React, { useState } from 'react';
import {
  Layers,
  Upload,
  Play,
  Download,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Trash2,
  Sparkles,
  ExternalLink
} from 'lucide-react';
import { ScanResult } from '../types';
import { createLocalScanResult } from '../lib/svm-engine';

interface BulkScannerProps {
  onSelectScan: (scan: ScanResult) => void;
}

const SAMPLE_BATCH = `https://github.com/security
http://paypa1-security-verification.xyz/login/verify.php
https://safety.google/authentication-security/
http://185.220.101.42:8080/chase-online/auth.html
https://accounts-google-drive-share.top/auth/signin
https://netflix.com
https://netf1ix-billing-update-account.com/renew`;

export const BulkScanner: React.FC<BulkScannerProps> = ({ onSelectScan }) => {
  const [urlsInput, setUrlsInput] = useState<string>(SAMPLE_BATCH);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleRunBatch = async () => {
    const lines = urlsInput
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    if (lines.length === 0) {
      setErrorMsg('Please enter at least one URL to analyze.');
      return;
    }

    setErrorMsg(null);
    setIsScanning(true);
    setResults([]);

    try {
      try {
        const response = await fetch('/api/batch-analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls: lines }),
        });

        if (response.ok) {
          const data = await response.json();
          if (data.results && data.results.length > 0) {
            setResults(data.results);
            return;
          }
        }
      } catch {
        // Fallback to local client engine
      }

      // Local batch processing fallback
      const localResults: ScanResult[] = lines.slice(0, 25).map((u) => createLocalScanResult(u));
      setResults(localResults);
    } catch (err: any) {
      setErrorMsg(err.message || 'Batch scanning error occurred.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      const text = evt.target?.result as string;
      if (text) {
        setUrlsInput(text);
      }
    };
    reader.readAsText(file);
  };

  const handleExportCsv = () => {
    const headers = 'URL,Domain,Verdict,RiskScore,TargetBrand\n';
    const rows = results
      .map(
        (r) =>
          `"${r.url}","${r.domain}","${r.threatLevel}",${r.riskScore},"${r.threatIntel?.targetedBrand || 'None'}"`
      )
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-batch-results-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const phishCount = results.filter((r) => r.isPhishing || r.threatLevel?.toUpperCase() === 'PHISHING').length;
  const safeCount = results.filter((r) => !r.isPhishing && (r.threatLevel?.toUpperCase() === 'SAFE' || r.threatLevel?.toUpperCase() === 'LOW' || r.riskScore < 30)).length;

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-mono font-bold">
          <Layers className="h-3.5 w-3.5 text-blue-600" />
          <span>High-Throughput Parallel URL Threat Classifier</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-blue-950">
          Batch & Multi-URL <span className="text-blue-600">Threat Scanner</span>
        </h1>
        <p className="text-sm text-blue-900/70 max-w-2xl mx-auto leading-relaxed">
          Scan lists of URLs or upload threat lists in bulk. Extract SVM features and calculate threat scores in parallel.
        </p>
      </div>

      {/* Input Card */}
      <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-4 shadow-xl shadow-blue-900/5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-blue-100 pb-3">
          <label className="text-xs font-extrabold uppercase tracking-wider text-blue-950">
            Target URL List (One URL per line)
          </label>

          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-bold text-blue-900 cursor-pointer transition-colors shadow-xs">
              <Upload className="h-3.5 w-3.5 text-blue-600" />
              <span>Import .txt / .csv</span>
              <input type="file" accept=".txt,.csv" onChange={handleFileUpload} className="hidden" />
            </label>

            <button
              onClick={() => setUrlsInput('')}
              className="p-2 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-700 cursor-pointer transition-colors"
              title="Clear input"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        <textarea
          rows={6}
          value={urlsInput}
          onChange={(e) => setUrlsInput(e.target.value)}
          placeholder="Paste list of URLs..."
          disabled={isScanning}
          className="w-full p-4 rounded-2xl bg-slate-50 border border-blue-200 text-blue-950 font-mono text-xs focus:outline-none focus:border-blue-600 leading-relaxed"
        />

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
          <span className="text-xs text-blue-900/70 font-mono font-bold">
            {urlsInput.split('\n').filter((l) => l.trim()).length} URLs ready for batch analysis
          </span>

          <button
            onClick={handleRunBatch}
            disabled={isScanning || !urlsInput.trim()}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 rounded-2xl bg-blue-600 hover:bg-blue-700 text-white font-extrabold text-xs shadow-md shadow-blue-600/20 transition-all disabled:opacity-50 cursor-pointer"
          >
            {isScanning ? (
              <>
                <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                <span>Processing Batch...</span>
              </>
            ) : (
              <>
                <Play className="h-4 w-4" />
                <span>Execute Batch Inspection</span>
              </>
            )}
          </button>
        </div>

        {errorMsg && (
          <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs font-medium">
            {errorMsg}
          </div>
        )}
      </div>

      {/* Batch Results View */}
      {results.length > 0 && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Summary Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-5 rounded-3xl bg-white border border-blue-100 text-center space-y-1 shadow-xs">
              <span className="text-[10px] font-mono uppercase font-bold text-blue-900/60">Total Scanned</span>
              <div className="text-2xl font-mono font-black text-blue-950">{results.length}</div>
            </div>

            <div className="p-5 rounded-3xl bg-white border border-rose-200 text-center space-y-1 shadow-xs">
              <span className="text-[10px] font-mono uppercase font-bold text-rose-700">Phishing Detected</span>
              <div className="text-2xl font-mono font-black text-rose-700">{phishCount}</div>
            </div>

            <div className="p-5 rounded-3xl bg-white border border-emerald-200 text-center space-y-1 shadow-xs">
              <span className="text-[10px] font-mono uppercase font-bold text-emerald-700">Legitimate Verified</span>
              <div className="text-2xl font-mono font-black text-emerald-700">{safeCount}</div>
            </div>

            <div className="p-5 rounded-3xl bg-white border border-blue-100 text-center space-y-1 shadow-xs">
              <span className="text-[10px] font-mono uppercase font-bold text-blue-900/60">Actions</span>
              <button
                onClick={handleExportCsv}
                className="mt-1 w-full py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Download className="h-3 w-3" />
                <span>Export CSV</span>
              </button>
            </div>
          </div>

          {/* Results Table */}
          <div className="overflow-hidden rounded-3xl bg-white border border-blue-100 shadow-xl shadow-blue-900/5">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-blue-50/80 border-b border-blue-100 font-mono text-blue-900 uppercase text-[10px]">
                  <tr>
                    <th className="px-4 py-3.5">Domain / URL</th>
                    <th className="px-4 py-3.5">Verdict</th>
                    <th className="px-4 py-3.5">Risk Score</th>
                    <th className="px-4 py-3.5">Targeted Brand</th>
                    <th className="px-4 py-3.5">SVM Decision f(x)</th>
                    <th className="px-4 py-3.5 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-blue-50">
                  {results.map((res, idx) => (
                    <tr
                      key={idx}
                      onClick={() => onSelectScan(res)}
                      className="hover:bg-blue-50/40 transition-colors cursor-pointer"
                    >
                      <td className="px-4 py-3.5 font-mono">
                        <div className="font-extrabold text-blue-950">{res.domain}</div>
                        <div className="text-[11px] text-blue-900/70 truncate max-w-xs">{res.url}</div>
                      </td>
                      <td className="px-4 py-3.5">
                        <span
                          className={`inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2.5 py-1 rounded-full ${
                            res.isPhishing || res.threatLevel?.toUpperCase() === 'PHISHING'
                              ? 'bg-rose-100 text-rose-800 border border-rose-200'
                              : res.threatLevel?.toUpperCase() === 'SUSPICIOUS'
                              ? 'bg-amber-100 text-amber-800 border border-amber-200'
                              : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                          }`}
                        >
                          {res.isPhishing || res.threatLevel?.toUpperCase() === 'PHISHING' ? (
                            <ShieldAlert className="h-3 w-3" />
                          ) : (
                            <ShieldCheck className="h-3 w-3" />
                          )}
                          <span>{res.threatLevel?.toUpperCase() || (res.isPhishing ? 'PHISHING' : 'SAFE')}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3.5 font-mono font-bold">
                        <span className={res.riskScore >= 70 ? 'text-rose-600' : (res.riskScore >= 30 ? 'text-amber-600' : 'text-emerald-700')}>
                          {res.riskScore}%
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-blue-950 font-semibold">
                        {res.threatIntel?.targetedBrand || <span className="text-blue-900/40">—</span>}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-blue-900 font-bold">
                        {res.svm?.decisionValue}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <span className="text-blue-600 text-xs font-bold hover:underline">
                          View Full Report →
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
