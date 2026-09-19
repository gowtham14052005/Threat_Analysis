import React, { useState } from 'react';
import {
  Puzzle,
  Globe,
  ShieldAlert,
  ShieldCheck,
  Download,
  Copy,
  Check,
  ExternalLink,
  ArrowLeft,
  ArrowRight,
  RotateCw,
  Lock,
  Unlock,
  AlertTriangle,
  Code2,
  FileCode2,
  Layers,
  ChevronDown
} from 'lucide-react';

const EXTENSION_FILES = {
  'manifest.json': `{
  "manifest_version": 3,
  "name": "PhishGuard SVM - Real-Time Phishing Protection",
  "version": "1.0.0",
  "description": "Real-time Support Vector Machine phishing detection and URL protection shield.",
  "permissions": [
    "activeTab",
    "storage",
    "declarativeNetRequest",
    "notifications"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "service_worker.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content_script.js"],
      "run_at": "document_start"
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  }
}`,

  'service_worker.js': `// PhishGuard SVM Background Service Worker (Manifest V3)
const SVM_API_ENDPOINT = "https://your-api.com/api/analyze";

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    try {
      // Perform fast local heuristic evaluation
      const url = new URL(tab.url);
      const isSuspicious = checkLocalHeuristics(url);

      if (isSuspicious) {
        // Query SVM detection API
        const response = await fetch(SVM_API_ENDPOINT, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: tab.url })
        });
        const result = await response.json();

        if (result.isPhishing) {
          // Set badge to danger
          chrome.action.setBadgeText({ tabId, text: "!" });
          chrome.action.setBadgeBackgroundColor({ tabId, color: "#e11d48" });

          // Send message to content script to intercept page
          chrome.tabs.sendMessage(tabId, {
            action: "PHISHGUARD_BLOCK",
            data: result
          });
        } else {
          chrome.action.setBadgeText({ tabId, text: "OK" });
          chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
        }
      }
    } catch (e) {
      console.warn("PhishGuard check error:", e);
    }
  }
});

function checkLocalHeuristics(urlObj) {
  const host = urlObj.hostname.toLowerCase();
  return (
    host.includes("paypa1") ||
    host.includes("login-secure") ||
    host.endsWith(".xyz") ||
    host.endsWith(".top") ||
    host.match(/\\d+\\.\\d+\\.\\d+\\.\\d+/)
  );
}`,

  'content_script.js': `// PhishGuard Content Script (DOM Interception)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "PHISHGUARD_BLOCK") {
    displayPhishGuardWarning(request.data);
  }
});

function displayPhishGuardWarning(threatData) {
  // Prevent form submissions
  document.querySelectorAll("form").forEach(f => {
    f.addEventListener("submit", e => {
      e.preventDefault();
      alert("PhishGuard Security Alert: Form submission disabled on this high-risk phishing page.");
    }, true);
  });

  // Inject warning banner
  const banner = document.createElement("div");
  banner.id = "phishguard-interception-modal";
  banner.innerHTML = \`
    <div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(2,6,23,0.95);z-index:9999999;display:flex;align-items:center;justify-content:center;font-family:sans-serif;color:white;padding:20px;">
      <div style="background:#0f172a;border:2px solid #ef4444;border-radius:16px;padding:32px;max-width:540px;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,0.7);">
        <h1 style="color:#f87171;font-size:24px;margin-bottom:8px;">⚠️ Deceptive Website Blocked</h1>
        <p style="color:#94a3b8;font-size:14px;margin-bottom:16px;">PhishGuard SVM detected this website is attempting to steal your credentials.</p>
        <div style="background:#020617;padding:12px;border-radius:8px;font-family:monospace;font-size:12px;color:#fca5a5;margin-bottom:20px;text-align:left;">
          Domain: \${threatData.domain}<br/>
          Risk Score: \${threatData.riskScore}%<br/>
          SVM Decision: Hyperplane Margin Exceeded
        </div>
        <button onclick="window.history.back()" style="background:#2563eb;color:white;border:none;padding:12px 24px;border-radius:8px;font-weight:bold;cursor:pointer;">Go Back to Safety</button>
      </div>
    </div>
  \`;
  document.body.appendChild(banner);
}`,

  'popup.html': `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { width: 300px; padding: 16px; margin: 0; background: #0f172a; color: #f8fafc; font-family: system-ui; }
    .header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 8px; }
    .title { font-weight: bold; font-size: 14px; color: #38bdf8; }
    .score-box { background: #020617; border-radius: 12px; padding: 16px; text-align: center; margin: 12px 0; border: 1px solid #1e293b; }
    .score { font-size: 32px; font-weight: 900; font-family: monospace; }
    .safe { color: #34d399; }
    .danger { color: #f87171; }
    .btn { width: 100%; background: #0284c7; color: white; border: none; padding: 8px; border-radius: 6px; font-weight: bold; cursor: pointer; }
  </style>
</head>
<body>
  <div class="header">
    <div class="title">PhishGuard Shield</div>
    <span style="font-size: 10px; color: #34d399;">Active</span>
  </div>
  <div class="score-box">
    <div style="font-size: 11px; color: #94a3b8;">Threat Risk Score</div>
    <div class="score safe" id="score">0%</div>
    <div style="font-size: 12px; font-weight: bold;" id="verdict">Legitimate Host</div>
  </div>
  <button class="btn" id="rescan">Deep AI Inspection</button>
</body>
</html>`
};

export const ExtensionSimulator: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<keyof typeof EXTENSION_FILES>('manifest.json');
  const [virtualUrl, setVirtualUrl] = useState<string>('http://paypa1-security-verification.xyz/login.php');
  const [isPhishingSite, setIsPhishingSite] = useState<boolean>(true);
  const [extensionPopupOpen, setExtensionPopupOpen] = useState<boolean>(false);
  const [showInPageBanner, setShowInPageBanner] = useState<boolean>(true);
  const [copiedFile, setCopiedFile] = useState<boolean>(false);

  const handleTestUrlChange = (url: string, isPhish: boolean) => {
    setVirtualUrl(url);
    setIsPhishingSite(isPhish);
    setShowInPageBanner(isPhish);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(EXTENSION_FILES[selectedFile]);
    setCopiedFile(true);
    setTimeout(() => setCopiedFile(false), 2000);
  };

  const handleDownloadAll = () => {
    const content = Object.entries(EXTENSION_FILES)
      .map(([name, code]) => `=== FILE: ${name} ===\n\n${code}\n\n`)
      .join('---------------------------------------------------\n');

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'phishguard-extension-manifest-v3.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-mono font-bold">
          <Puzzle className="h-3.5 w-3.5 text-blue-600" />
          <span>Chrome / Firefox Web Protection Manifest V3</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-blue-950">
          Real-Time <span className="text-blue-600">Browser Extension Simulator</span>
        </h1>
        <p className="text-sm text-blue-900/70 max-w-2xl mx-auto leading-relaxed">
          Test real-time in-browser address bar heuristics, active interception modals, extension toolbar badges, and download the full Manifest V3 source code.
        </p>
      </div>

      {/* Interactive Browser Sandbox Mockup */}
      <div className="rounded-3xl bg-white border border-blue-100 shadow-xl shadow-blue-900/5 overflow-hidden">
        {/* Browser Top Chrome / Titlebar */}
        <div className="bg-slate-100 px-4 py-3 border-b border-blue-100 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="h-3 w-3 rounded-full bg-rose-500" />
            <div className="h-3 w-3 rounded-full bg-amber-500" />
            <div className="h-3 w-3 rounded-full bg-emerald-500" />
            <span className="text-xs font-mono font-bold text-blue-950 ml-2 hidden sm:inline">
              Virtual Chrome Browser Sandbox (V8 Engine)
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleTestUrlChange('http://paypa1-security-verification.xyz/login.php', true)}
              className={`px-3 py-1 rounded-xl text-xs font-mono font-bold transition-colors cursor-pointer ${
                isPhishingSite ? 'bg-rose-100 text-rose-800 border border-rose-200' : 'text-blue-900/60 hover:text-blue-950 bg-white'
              }`}
            >
              Test Phishing Site
            </button>
            <button
              onClick={() => handleTestUrlChange('https://github.com/security', false)}
              className={`px-3 py-1 rounded-xl text-xs font-mono font-bold transition-colors cursor-pointer ${
                !isPhishingSite ? 'bg-emerald-100 text-emerald-800 border border-emerald-200' : 'text-blue-900/60 hover:text-blue-950 bg-white'
              }`}
            >
              Test Safe Site
            </button>
          </div>
        </div>

        {/* Address Bar & Extension Toolbar */}
        <div className="bg-white px-4 py-3 border-b border-blue-100 flex items-center gap-3">
          <div className="flex items-center gap-2 text-blue-400">
            <ArrowLeft className="h-4 w-4 hover:text-blue-900 cursor-pointer" />
            <ArrowRight className="h-4 w-4 hover:text-blue-900 cursor-pointer" />
            <RotateCw className="h-4 w-4 hover:text-blue-900 cursor-pointer" />
          </div>

          {/* Omnibox / Address Bar */}
          <div className="flex-1 flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-xs font-mono">
            {isPhishingSite ? (
              <Unlock className="h-3.5 w-3.5 text-rose-600 shrink-0" />
            ) : (
              <Lock className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
            )}
            <span className="text-blue-900/50">{isPhishingSite ? 'http://' : 'https://'}</span>
            <span className={isPhishingSite ? 'text-rose-700 font-extrabold' : 'text-emerald-800 font-extrabold'}>
              {virtualUrl.replace(/https?:\/\//, '')}
            </span>
          </div>

          {/* Extension Icon on Toolbar */}
          <div className="relative">
            <button
              id="extension-toolbar-icon"
              onClick={() => setExtensionPopupOpen(!extensionPopupOpen)}
              className={`relative p-2 rounded-xl border transition-all cursor-pointer ${
                isPhishingSite
                  ? 'bg-rose-50 border-rose-200 text-rose-700'
                  : 'bg-emerald-50 border-emerald-200 text-emerald-700'
              }`}
              title="PhishGuard Extension"
            >
              <Puzzle className="h-4 w-4" />
              {/* Badge */}
              <span
                className={`absolute -top-1 -right-1 h-4 w-4 rounded-full text-[9px] font-bold flex items-center justify-center text-white ${
                  isPhishingSite ? 'bg-rose-600' : 'bg-emerald-600'
                }`}
              >
                {isPhishingSite ? '!' : '✓'}
              </span>
            </button>

            {/* Interactive Extension Popup Overlay */}
            {extensionPopupOpen && (
              <div className="absolute right-0 mt-2 w-72 rounded-3xl bg-white border border-blue-200 shadow-2xl p-5 z-50 animate-in fade-in slide-in-from-top-2">
                <div className="flex items-center justify-between border-b border-blue-100 pb-2.5">
                  <div className="flex items-center gap-1.5 font-bold text-xs text-blue-950">
                    <Puzzle className="h-4 w-4 text-blue-600" />
                    <span>PhishGuard Shield</span>
                  </div>
                  <span className="text-[10px] font-mono font-bold text-emerald-700">● Active</span>
                </div>

                <div className="my-3 p-3.5 rounded-2xl bg-blue-50 border border-blue-100 text-center space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-blue-900/60">Threat Risk Score</span>
                  <div
                    className={`text-2xl font-mono font-black ${
                      isPhishingSite ? 'text-rose-600' : 'text-emerald-700'
                    }`}
                  >
                    {isPhishingSite ? '96%' : '4%'}
                  </div>
                  <span
                    className={`inline-block text-xs font-bold ${
                      isPhishingSite ? 'text-rose-800' : 'text-emerald-800'
                    }`}
                  >
                    {isPhishingSite ? '🚨 Phishing Malicious Site' : '🛡️ Legitimate Verified'}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs text-blue-950 font-medium">
                  <div className="flex justify-between py-1 border-b border-blue-50">
                    <span className="text-blue-900/60">SVM Hyperplane:</span>
                    <span className="font-mono font-bold">{isPhishingSite ? 'f(x) = -2.84' : 'f(x) = +3.12'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-blue-50">
                    <span className="text-blue-900/60">Form Interception:</span>
                    <span className="text-blue-600 font-bold">Active</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-blue-900/60">Threat Feed Sync:</span>
                    <span className="text-emerald-700 font-bold">Real-time</span>
                  </div>
                </div>

                <button
                  onClick={() => setShowInPageBanner(true)}
                  className="w-full mt-3 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition-colors cursor-pointer"
                >
                  View In-Page Security Banner
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Webpage Content Area / Simulated Page View */}
        <div className="relative min-h-[340px] bg-slate-50 p-6 flex flex-col justify-center items-center">
          {/* Simulated Phishing Interception Modal */}
          {isPhishingSite && showInPageBanner ? (
            <div className="max-w-xl w-full p-6 sm:p-8 rounded-3xl bg-white border-2 border-rose-500 shadow-2xl space-y-4 animate-in zoom-in-95 duration-200">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-2xl bg-rose-100 text-rose-700 border border-rose-200">
                  <ShieldAlert className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="text-lg font-extrabold text-rose-700">PhishGuard SVM Interception</h3>
                  <p className="text-xs text-blue-900/70">
                    High-Risk Deceptive Phishing Website Blocked Before Form Submission
                  </p>
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-rose-50/60 border border-rose-200 text-xs space-y-1 font-mono">
                <div className="text-blue-950 font-medium">
                  Target Domain: <strong className="text-rose-700">paypa1-security-verification.xyz</strong>
                </div>
                <div className="text-rose-700">
                  Reason: SVM Classifier detected Typo-Squatting + High-Risk .xyz TLD + Credential Harvesting Vector.
                </div>
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={() => handleTestUrlChange('https://google.com', false)}
                  className="flex-1 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-md shadow-blue-600/20 transition-colors cursor-pointer"
                >
                  Return to Safety
                </button>
                <button
                  onClick={() => setShowInPageBanner(false)}
                  className="px-4 py-2.5 rounded-xl bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Proceed Anyway (Unsafe)
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center space-y-3 p-8">
              <div className="h-12 w-12 rounded-full bg-emerald-100 text-emerald-700 border border-emerald-200 flex items-center justify-center mx-auto">
                <ShieldCheck className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-extrabold text-blue-950">
                {isPhishingSite ? 'Simulated Dangerous Webpage (Unprotected View)' : 'Legitimate Verified Website'}
              </h3>
              <p className="text-xs text-blue-900/70 max-w-md mx-auto leading-relaxed">
                {isPhishingSite
                  ? 'You bypassed the PhishGuard protection shield. In production, password inputs and form actions are actively neutralized.'
                  : 'Domain verified with valid SSL certificate, long-term DNS authority, and clean reputation telemetry.'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Manifest V3 Source Code Explorer */}
      <div className="rounded-3xl bg-white border border-blue-100 p-6 space-y-4 shadow-xl shadow-blue-900/5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-blue-100 pb-3">
          <div>
            <h3 className="text-base font-extrabold text-blue-950 flex items-center gap-2">
              <Code2 className="h-4 w-4 text-blue-600" />
              <span>Manifest V3 Extension Source Code Package</span>
            </h3>
            <p className="text-xs text-blue-900/60">
              Ready-to-load Chrome/Edge/Firefox Web Protection extension
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyCode}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-bold text-blue-900 transition-colors cursor-pointer"
            >
              {copiedFile ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5 text-blue-600" />}
              <span>{copiedFile ? 'Copied' : 'Copy Current File'}</span>
            </button>

            <button
              onClick={handleDownloadAll}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition-all cursor-pointer"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Download Extension Bundle</span>
            </button>
          </div>
        </div>

        {/* File Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 no-scrollbar">
          {(Object.keys(EXTENSION_FILES) as Array<keyof typeof EXTENSION_FILES>).map((fileName) => (
            <button
              key={fileName}
              onClick={() => setSelectedFile(fileName)}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-mono transition-colors cursor-pointer ${
                selectedFile === fileName
                  ? 'bg-blue-600 text-white font-bold shadow-xs'
                  : 'bg-blue-50 text-blue-900/70 hover:text-blue-950 border border-blue-100'
              }`}
            >
              <FileCode2 className="h-3.5 w-3.5" />
              <span>{fileName}</span>
            </button>
          ))}
        </div>

        {/* Code View */}
        <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 overflow-x-auto max-h-96 font-mono text-xs text-slate-100 leading-relaxed">
          <pre>{EXTENSION_FILES[selectedFile]}</pre>
        </div>
      </div>
    </div>
  );
};
