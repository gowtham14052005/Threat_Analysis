import React, { useState, useMemo } from 'react';
import {
  Cpu,
  Sliders,
  Sparkles,
  BarChart3,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  BookOpen,
  Zap,
  TrendingUp,
  Layers,
  Lightbulb,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Lock,
  Globe,
  Check,
  XCircle
} from 'lucide-react';
import { SVM_FEATURE_WEIGHTS, SVM_BIAS } from '../lib/svm-engine';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

export const SvmExplorer: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'beginner' | 'advanced'>('beginner');
  const [selectedKernel, setSelectedKernel] = useState<'rbf' | 'linear' | 'poly'>('rbf');
  const [cParam, setCParam] = useState<number>(1.25);
  const [gammaParam, setGammaParam] = useState<number>(0.045);
  const [polyDegree, setPolyDegree] = useState<number>(3);

  // Interactive Live Feature Tester State
  const [testFeatures, setTestFeatures] = useState<Record<string, number>>({
    ssl_state: -1, // -1 (HTTP) vs 1 (HTTPS)
    domain_age: -1, // -1 (<6 mos) vs 1 (>1 yr)
    prefix_suffix_hyphen: -1, // -1 (Has hyphen) vs 1 (No hyphen)
    sub_domains_count: -1, // -1 (Many) vs 1 (Standard)
    server_form_handler: -1, // -1 (External/Blank) vs 1 (Same-origin)
    url_length: -1, // -1 (>75 chars) vs 1 (Short)
    punycode_homoglyph: 1, // 1 (Clean) vs -1 (Spoofed)
    https_token_in_domain: -1, // -1 (Injected) vs 1 (Clean)
  });

  // Calculate live decision value based on interactive sliders
  const liveDecision = useMemo(() => {
    let sum = SVM_BIAS;
    Object.entries(testFeatures).forEach(([key, val]) => {
      const weight = SVM_FEATURE_WEIGHTS[key]?.weight || 1.0;
      const numVal = typeof val === 'number' ? val : Number(val) || 0;
      sum += weight * numVal;
    });

    if (selectedKernel === 'rbf') {
      const rbfAdjustment = Math.exp(-gammaParam * 15);
      sum = sum * 0.6 + (sum > 0 ? 1 : -1) * (1 - rbfAdjustment) * 4;
    } else if (selectedKernel === 'poly') {
      sum = Math.pow(Math.max(-3, Math.min(3, sum)), polyDegree) * 0.2;
    }

    const isPhish = sum < 0;
    const confidence = Math.min(99.6, Math.max(55, Math.round(Math.abs(sum) * 12 + 50)));
    const riskScore = Math.max(0, Math.min(100, Math.round(50 - sum * 15)));

    return {
      value: Number(sum.toFixed(3)),
      isPhish,
      confidence,
      riskScore,
    };
  }, [testFeatures, selectedKernel, gammaParam, polyDegree]);

  // All 24 feature weights sorted for chart
  const featureWeightsData = useMemo(() => {
    return Object.entries(SVM_FEATURE_WEIGHTS)
      .map(([id, info]) => ({
        id,
        name: info.name.length > 22 ? info.name.substring(0, 20) + '...' : info.name,
        weight: info.weight,
        category: info.category,
      }))
      .sort((a, b) => b.weight - a.weight);
  }, []);

  const handleResetFeatures = () => {
    setTestFeatures({
      ssl_state: -1,
      domain_age: -1,
      prefix_suffix_hyphen: -1,
      sub_domains_count: -1,
      server_form_handler: -1,
      url_length: -1,
      punycode_homoglyph: 1,
      https_token_in_domain: -1,
    });
  };

  const handleMakeSafe = () => {
    setTestFeatures({
      ssl_state: 1,
      domain_age: 1,
      prefix_suffix_hyphen: 1,
      sub_domains_count: 1,
      server_form_handler: 1,
      url_length: 1,
      punycode_homoglyph: 1,
      https_token_in_domain: 1,
    });
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-bold">
          <Cpu className="h-4 w-4 text-blue-600" />
          <span>Interactive Machine Learning & AI Lab</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-blue-950 tracking-tight">
          How AI Spots <span className="text-blue-600">Dangerous Links</span>
        </h1>
        <p className="text-sm text-blue-900/70 max-w-2xl mx-auto leading-relaxed">
          Explore how a Support Vector Machine (SVM) evaluates indicators like domain age, SSL encryption, and typo tricks to classify safe vs malicious links.
        </p>

        {/* Tab Switcher */}
        <div className="flex items-center justify-center pt-2">
          <div className="inline-flex items-center p-1.5 rounded-2xl bg-white border border-blue-200 shadow-xs">
            <button
              onClick={() => setActiveTab('beginner')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'beginner'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                  : 'text-blue-900/70 hover:text-blue-950'
              }`}
            >
              <Lightbulb className="h-4 w-4" />
              <span>Beginner Friendly Guide</span>
            </button>
            <button
              onClick={() => setActiveTab('advanced')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'advanced'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                  : 'text-blue-900/70 hover:text-blue-950'
              }`}
            >
              <Sliders className="h-4 w-4" />
              <span>Advanced Mathematics Lab</span>
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: BEGINNER FRIENDLY GUIDE & INTERACTIVE URL BUILDER                  */}
      {/* ========================================================================= */}
      {activeTab === 'beginner' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* 3 Step Visual Analogy */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xl shadow-blue-900/5">
              <div className="h-9 w-9 rounded-2xl bg-blue-50 text-blue-700 font-extrabold text-xs flex items-center justify-center border border-blue-200">
                1
              </div>
              <h3 className="text-sm font-extrabold text-blue-950">Extract Clues (Features)</h3>
              <p className="text-xs text-blue-900/70 leading-relaxed">
                When you scan a link, the AI inspects 24 specific traits: Is it encrypted? Is the name misspelled? How old is the website?
              </p>
            </div>

            <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xl shadow-blue-900/5">
              <div className="h-9 w-9 rounded-2xl bg-blue-50 text-blue-700 font-extrabold text-xs flex items-center justify-center border border-blue-200">
                2
              </div>
              <h3 className="text-sm font-extrabold text-blue-950">Weigh the Evidence</h3>
              <p className="text-xs text-blue-900/70 leading-relaxed">
                Some red flags carry heavy penalties (e.g. asking for passwords on an unencrypted page), while trusted traits add positive points.
              </p>
            </div>

            <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xl shadow-blue-900/5">
              <div className="h-9 w-9 rounded-2xl bg-blue-50 text-blue-700 font-extrabold text-xs flex items-center justify-center border border-blue-200">
                3
              </div>
              <h3 className="text-sm font-extrabold text-blue-950">Draw the Decision Line</h3>
              <p className="text-xs text-blue-900/70 leading-relaxed">
                The SVM calculates the total score. If it crosses into the danger zone, it triggers an instant warning to keep you safe.
              </p>
            </div>
          </div>

          {/* Interactive URL Playground */}
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-blue-100 pb-4">
              <div>
                <h2 className="text-base font-extrabold text-blue-950 flex items-center gap-2">
                  <Sliders className="h-5 w-5 text-blue-600" />
                  <span>Interactive Link Safety Simulator</span>
                </h2>
                <p className="text-xs text-blue-900/70 mt-0.5">
                  Toggle clues below to see in real-time how the AI determines if a link is safe or dangerous!
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleMakeSafe}
                  className="px-3.5 py-1.5 rounded-xl bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 text-xs font-bold transition-colors cursor-pointer"
                >
                  Make 100% Safe
                </button>
                <button
                  onClick={handleResetFeatures}
                  className="px-3.5 py-1.5 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-800 border border-rose-200 text-xs font-bold transition-colors cursor-pointer"
                >
                  Make Scam / Phishing
                </button>
              </div>
            </div>

            {/* Live Verdict Banner */}
            <div
              className={`p-6 rounded-3xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 transition-all duration-300 ${
                liveDecision.isPhish
                  ? 'bg-rose-50/70 border-rose-200 shadow-lg shadow-rose-950/5'
                  : 'bg-emerald-50/70 border-emerald-200 shadow-lg shadow-emerald-950/5'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={`text-xs font-black uppercase tracking-wider px-3 py-1 rounded-full text-white ${
                      liveDecision.isPhish ? 'bg-rose-600' : 'bg-emerald-600'
                    }`}
                  >
                    {liveDecision.isPhish ? '🚨 AI VERDICT: DANGEROUS SCAM' : '🛡️ AI VERDICT: SAFE LINK'}
                  </span>
                  <span className="text-xs font-bold text-blue-950">
                    Confidence: <strong className="text-blue-700">{liveDecision.confidence}%</strong>
                  </span>
                </div>
                <p className="text-xs text-blue-950 font-medium">
                  {liveDecision.isPhish
                    ? 'The AI detected multiple severe warning signs. A user visiting this link would be warned immediately.'
                    : 'The link features look healthy, authentic, and verified.'}
                </p>
              </div>

              {/* Visual Meter */}
              <div className="flex items-center gap-3 shrink-0">
                <div className="text-right">
                  <span className="text-[10px] uppercase font-bold text-blue-900/60 block">Threat Risk</span>
                  <span
                    className={`text-2xl font-black ${
                      liveDecision.isPhish ? 'text-rose-700' : 'text-emerald-700'
                    }`}
                  >
                    {liveDecision.riskScore}%
                  </span>
                </div>
              </div>
            </div>

            {/* Everyday Clues Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {[
                {
                  id: 'ssl_state',
                  label: 'Security Lock (HTTPS)',
                  hint: 'Does the website encrypt your connection?',
                  safeLabel: '🔒 Encrypted (Safe)',
                  riskLabel: '🔓 Unencrypted (Risk)',
                },
                {
                  id: 'domain_age',
                  label: 'Website Age',
                  hint: 'How long has this domain existed?',
                  safeLabel: '⏳ > 1 Year (Established)',
                  riskLabel: '🚨 Created Recently (Suspicious)',
                },
                {
                  id: 'prefix_suffix_hyphen',
                  label: 'Domain Name Spelling',
                  hint: 'Does it use suspicious hyphen tricks?',
                  safeLabel: '✨ Clean Name',
                  riskLabel: '⚠️ Hyphens (e.g. login-bank)',
                },
                {
                  id: 'sub_domains_count',
                  label: 'Subdomain Stacking',
                  hint: 'Too many fake dots in the address?',
                  safeLabel: '✨ Standard Address',
                  riskLabel: '⚠️ paypal.verify.account.xyz',
                },
                {
                  id: 'server_form_handler',
                  label: 'Password Form Handler',
                  hint: 'Where do typed passwords get sent?',
                  safeLabel: '🛡️ Official Server',
                  riskLabel: '🚨 Sent to Unknown Third-Party',
                },
                {
                  id: 'url_length',
                  label: 'Web Link Length',
                  hint: 'Is the link abnormally long?',
                  safeLabel: '✨ Normal Length',
                  riskLabel: '⚠️ Over 75 Characters Long',
                },
                {
                  id: 'punycode_homoglyph',
                  label: 'Letter Spoofing',
                  hint: 'Does it use lookalike Russian/Cyrillic letters?',
                  safeLabel: '✨ Standard Letters',
                  riskLabel: '🚨 Lookalike Spoofing (xn--)',
                },
                {
                  id: 'https_token_in_domain',
                  label: 'Fake "https" in Name',
                  hint: 'Does it fake https:// in the middle of text?',
                  safeLabel: '✨ Clean Host',
                  riskLabel: '🚨 Injected "https-verify"',
                },
              ].map((item) => {
                const currentVal = testFeatures[item.id] ?? 1;
                const isSafe = currentVal === 1;
                return (
                  <div key={item.id} className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-3">
                    <div>
                      <h4 className="text-xs font-extrabold text-blue-950">{item.label}</h4>
                      <p className="text-[11px] text-blue-900/70 mt-0.5">{item.hint}</p>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => setTestFeatures({ ...testFeatures, [item.id]: 1 })}
                        className={`py-2 px-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                          isSafe
                            ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-600/20'
                            : 'bg-white text-blue-900/70 border border-blue-200 hover:text-blue-950'
                        }`}
                      >
                        Safe (+1)
                      </button>
                      <button
                        onClick={() => setTestFeatures({ ...testFeatures, [item.id]: -1 })}
                        className={`py-2 px-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                          !isSafe
                            ? 'bg-rose-600 text-white shadow-sm shadow-rose-600/20'
                            : 'bg-white text-blue-900/70 border border-blue-200 hover:text-blue-950'
                        }`}
                      >
                        Scam (-1)
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: ADVANCED MATHEMATICAL LAB (Hyperplanes, Kernels, Weights)          */}
      {/* ========================================================================= */}
      {activeTab === 'advanced' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-blue-100 pb-4">
              <div>
                <h2 className="text-base font-extrabold text-blue-950 flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-blue-600" />
                  <span>Hyperplane Decision Boundary & Kernel Transformation</span>
                </h2>
                <p className="text-xs text-blue-900/70 font-mono">
                  Evaluate mathematical formulation: f(x) = sgn(∑ αᵢ yᵢ K(xᵢ, x) + b)
                </p>
              </div>

              <div className="flex items-center gap-2">
                <div className="flex rounded-xl bg-blue-50 p-1 border border-blue-200 text-xs font-mono">
                  <button
                    onClick={() => setSelectedKernel('rbf')}
                    className={`px-3 py-1 rounded-lg cursor-pointer font-bold ${
                      selectedKernel === 'rbf' ? 'bg-blue-600 text-white shadow-xs' : 'text-blue-900/70 hover:text-blue-950'
                    }`}
                  >
                    RBF (Gaussian)
                  </button>
                  <button
                    onClick={() => setSelectedKernel('linear')}
                    className={`px-3 py-1 rounded-lg cursor-pointer font-bold ${
                      selectedKernel === 'linear' ? 'bg-blue-600 text-white shadow-xs' : 'text-blue-900/70 hover:text-blue-950'
                    }`}
                  >
                    Linear
                  </button>
                  <button
                    onClick={() => setSelectedKernel('poly')}
                    className={`px-3 py-1 rounded-lg cursor-pointer font-bold ${
                      selectedKernel === 'poly' ? 'bg-blue-600 text-white shadow-xs' : 'text-blue-900/70 hover:text-blue-950'
                    }`}
                  >
                    Polynomial
                  </button>
                </div>

                <button
                  onClick={handleResetFeatures}
                  className="p-2 rounded-xl bg-blue-50 border border-blue-200 text-blue-700 hover:bg-blue-100 text-xs cursor-pointer"
                  title="Reset features"
                >
                  <RotateCcw className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Live SVM Math Values */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-1 font-mono">
                <span className="text-[10px] uppercase font-bold text-blue-900/60">f(x) Decision Value</span>
                <p className={`text-xl font-bold ${liveDecision.isPhish ? 'text-rose-700' : 'text-emerald-700'}`}>
                  {liveDecision.value > 0 ? `+${liveDecision.value}` : liveDecision.value}
                </p>
                <p className="text-[10px] text-blue-900/70">Separating hyperplane distance</p>
              </div>

              <div className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-1 font-mono">
                <span className="text-[10px] uppercase font-bold text-blue-900/60">Kernel Parameter (γ)</span>
                <p className="text-xl font-bold text-indigo-700">{gammaParam}</p>
                <p className="text-[10px] text-blue-900/70">RBF variance parameter</p>
              </div>

              <div className="p-4 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-1 font-mono">
                <span className="text-[10px] uppercase font-bold text-blue-900/60">Regularization (C)</span>
                <p className="text-xl font-bold text-blue-700">{cParam}</p>
                <p className="text-[10px] text-blue-900/70">Slack penalty margin</p>
              </div>
            </div>

            {/* Hyperparameter Sliders */}
            <div className="p-5 rounded-2xl bg-blue-50/40 border border-blue-100 grid grid-cols-1 sm:grid-cols-2 gap-6">
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-blue-950 font-bold">C (Soft Margin Penalty)</span>
                  <span className="text-blue-700 font-black">{cParam}</span>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="10.0"
                  step="0.05"
                  value={cParam}
                  onChange={(e) => setCParam(parseFloat(e.target.value))}
                  className="w-full accent-blue-600 cursor-pointer"
                />
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-blue-950 font-bold">Gamma (γ Kernel Spread)</span>
                  <span className="text-indigo-700 font-black">{gammaParam}</span>
                </div>
                <input
                  type="range"
                  min="0.005"
                  max="0.5"
                  step="0.005"
                  value={gammaParam}
                  onChange={(e) => setGammaParam(parseFloat(e.target.value))}
                  className="w-full accent-indigo-600 cursor-pointer"
                />
              </div>
            </div>

            {/* Feature Weights Chart */}
            <div className="space-y-3 pt-2">
              <h3 className="text-xs font-extrabold uppercase tracking-wider text-blue-950 flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-blue-600" />
                <span>All 24 Academic Feature Weights (Trained SVM Model)</span>
              </h3>

              <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={featureWeightsData} layout="vertical" margin={{ top: 5, right: 20, left: 30, bottom: 5 }}>
                    <XAxis type="number" stroke="#64748b" fontSize={11} />
                    <YAxis type="category" dataKey="name" stroke="#1e3a8a" fontSize={10} width={130} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#ffffff', borderColor: '#bfdbfe', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                      itemStyle={{ color: '#172554', fontSize: '12px', fontWeight: 'bold' }}
                    />
                    <Bar dataKey="weight" fill="#2563eb" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
