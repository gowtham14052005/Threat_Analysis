import React, { useState } from 'react';
import {
  Server,
  Cpu,
  Database,
  Globe,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Layers,
  Sparkles,
  Lock,
  Radio,
  FileCode2,
  Workflow,
  CheckCircle2,
  Zap,
  Activity,
  HardDrive,
  Code2,
  Share2,
  Copy,
  Check,
  Terminal,
  ExternalLink,
  ChevronRight,
  Sliders
} from 'lucide-react';

interface ComponentNode {
  id: string;
  name: string;
  category: 'frontend' | 'backend' | 'ml' | 'ai' | 'database' | 'intel';
  tag: string;
  status: 'Operational' | 'Active' | 'Synchronized';
  latency: string;
  description: string;
  techStack: string[];
  inputs: string[];
  outputs: string[];
  securityRole: string;
  featuresCount?: number;
}

export const ProjectInfrastructure: React.FC = () => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>('svm_engine');
  const [copiedSchema, setCopiedSchema] = useState(false);
  const [activeTab, setActiveTab] = useState<'blueprint' | 'layers' | 'dataflow' | 'techstack'>('blueprint');

  const infrastructureNodes: Record<string, ComponentNode> = {
    client_ui: {
      id: 'client_ui',
      name: 'Client Interface & Browser Extension',
      category: 'frontend',
      tag: 'Presentation Layer',
      status: 'Operational',
      latency: '< 15ms',
      description: 'Single-page responsive application built with React 18, Vite, and Tailwind CSS. Features dual-mode threat visualization ("Easy View" for everyday consumers and "Cyber Pro" for SOC analysts), real-time link simulation, and Chrome WebRequest hook simulation.',
      techStack: ['React 18', 'TypeScript', 'Tailwind CSS', 'Lucide Icons', 'Recharts D3'],
      inputs: ['Raw User URL String', 'Batch URL CSV', 'User Authentication Credentials'],
      outputs: ['Sanitized URL Payload', 'Export Formats (JSON/CSV/PDF)', 'Real-time Safety Alerts'],
      securityRole: 'Input sanitization, XSS mitigation, secure local storage caching, CSP headers.',
    },
    url_parser: {
      id: 'url_parser',
      name: 'URL Lexical & Heuristic Feature Extractor',
      category: 'backend',
      tag: 'Feature Engineering',
      status: 'Active',
      latency: '~25ms',
      description: 'Parses input web addresses into 24 distinct feature vectors defined by academic phishing benchmarks (UCI Machine Learning Repository). Evaluates lexical entropy, Punycode/homoglyph spoofing, multi-level subdomain depth, hyphen injection, and port anomalies.',
      techStack: ['Node.js Lexical Analyzer', 'Punycode / Unicode Decoder', 'URL Parsing Standard WHATWG'],
      inputs: ['Full URL String (HTTP/HTTPS)'],
      outputs: ['24-Dimensional Numeric Feature Vector (values ∈ {-1, 0, +1})', 'Normalized Weights Matrix'],
      securityRole: 'Converts unstructured string inputs into deterministic machine-learning feature tensors.',
      featuresCount: 24,
    },
    svm_engine: {
      id: 'svm_engine',
      name: 'Dual-Kernel Support Vector Machine (SVM) Classifier',
      category: 'ml',
      tag: 'Machine Learning Core',
      status: 'Operational',
      latency: '~12ms',
      description: 'Calculates the optimal separating hyperplane decision function f(x) = sgn(∑ αᵢ yᵢ K(xᵢ, x) + b). Supports Radial Basis Function (RBF) Gaussian kernels for non-linear decision boundaries and Linear kernels with L2 regularization (C=1.25, γ=0.045).',
      techStack: ['TypeScript SVM Engine', 'RBF Gaussian Kernel', 'Linear Kernel Matrix', 'Platt Scaling Probabilities'],
      inputs: ['24 Feature Vector', 'Hyperparameters (C, Gamma, Bias)'],
      outputs: ['Classification Verdict (Legitimate +1 vs Phishing -1)', 'Decision Value f(x)', 'Confidence Score % (50-99.8%)'],
      securityRole: 'Deterministic mathematical classification immune to prompt injection or hallucination.',
    },
    gemini_xai: {
      id: 'gemini_xai',
      name: 'Google Gemini 2.5 Explainable AI (XAI) Synthesizer',
      category: 'ai',
      tag: 'Explainability & Intelligence',
      status: 'Operational',
      latency: '~380ms',
      description: 'Translates high-dimensional SVM mathematical decision boundaries into human-readable plain English explanations, attack vector classifications (Credential Harvesting, Drive-by Download), MITRE ATT&CK technique mappings, and actionable SOC mitigation steps.',
      techStack: ['@google/genai SDK', 'Gemini 2.5 Flash', 'Server-side API Proxy', 'Zero-shot Reasoning'],
      inputs: ['Feature Impact Weights', 'Domain Age / SSL Telemetry', 'SVM Hyperplane Distance'],
      outputs: ['Natural Language Verdict Summary', 'Primary Risk Factors', 'Actionable Mitigation Checklist', 'MITRE ATT&CK IDs'],
      securityRole: 'Converts raw machine learning scores into actionable defense guidance for humans.',
    },
    threat_intel: {
      id: 'threat_intel',
      name: 'Threat Feeds & Global Blacklist Aggregator',
      category: 'intel',
      tag: 'Intelligence Feeds',
      status: 'Synchronized',
      latency: '~65ms',
      description: 'Cross-checks target domains against real-time global telemetry repositories including Google Safe Browsing, VirusTotal heuristics, PhishTank feeds, and SSL certificate trust registries.',
      techStack: ['Google Safe Browsing API v4', 'WHOIS RDAP Protocol', 'DNSSEC Over HTTPS (DoH)', 'SSL/TLS Verifier'],
      inputs: ['Root Domain Name', 'Host IP Address'],
      outputs: ['Domain Age (Days)', 'Certificate Issuer & Expiry', 'Blacklist Reputation Status', 'Targeted Brand Name'],
      securityRole: 'Independent external verification preventing false negatives for novel zero-day attacks.',
    },
    firebase_db: {
      id: 'firebase_db',
      name: 'Firebase Firestore Cloud Database & Auth Broker',
      category: 'database',
      tag: 'Persistence & Auth',
      status: 'Synchronized',
      latency: '~45ms',
      description: 'Provides durable cloud persistence for audit trail scan logs, security alerts triage, SOC incident response workflows, user profiles, and organization-wide domain whitelists / blacklists.',
      techStack: ['Firebase Firestore', 'Firebase Authentication', 'Security Rules Engine', 'Real-time WebSockets'],
      inputs: ['Scan Audit Records', 'Security Alert Statuses', 'Whitelist/Blacklist Entries'],
      outputs: ['Persistent Historical Analytics', 'Real-time Alert Notifications', 'User Role-Based Access Control'],
      securityRole: 'Durable data persistence, role-based access control, encrypted data at rest and in transit.',
    },
  };

  const selectedNode = infrastructureNodes[selectedNodeId] || infrastructureNodes['svm_engine'];

  const samplePipelinePayload = {
    pipeline_id: 'phishguard-infra-v2.4',
    url_target: 'http://paypa1-verification-login.xyz/account',
    infrastructure_layers: [
      { layer: 1, name: 'Client Presentation', framework: 'React 18 + Vite' },
      { layer: 2, name: 'Lexical Feature Extractor', total_features: 24, score: -1 },
      { layer: 3, name: 'Dual-Kernel SVM', kernel: 'RBF Gaussian', decision_val: -3.84, risk_score: 94 },
      { layer: 4, name: 'Explainable AI', engine: 'Gemini 2.5 Flash', threat_vector: 'Credential Harvesting' },
      { layer: 5, name: 'Database Persistence', cloud: 'Google Cloud Firebase Firestore' }
    ]
  };

  const handleCopyPayload = () => {
    navigator.clipboard.writeText(JSON.stringify(samplePipelinePayload, null, 2));
    setCopiedSchema(true);
    setTimeout(() => setCopiedSchema(false), 2000);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-semibold shadow-sm">
          <Workflow className="h-4 w-4 text-blue-600" />
          <span>System Architecture & Engineering Design</span>
        </div>
        <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold text-blue-950 tracking-tight">
          Project <span className="bg-gradient-to-r from-blue-700 via-blue-600 to-indigo-700 bg-clip-text text-transparent">Infrastructure</span> Design
        </h1>
        <p className="text-sm sm:text-base text-blue-900/80 max-w-3xl mx-auto leading-relaxed">
          Comprehensive blueprint of how URL inputs flow through lexical parsing, Support Vector Machine (SVM) mathematical classification, Gemini Explainable AI (XAI), and real-time Firestore synchronization.
        </p>

        {/* View Switcher Tabs */}
        <div className="flex items-center justify-center pt-2">
          <div className="inline-flex items-center p-1 rounded-xl bg-blue-50 border border-blue-200 shadow-sm">
            {[
              { id: 'blueprint', label: 'End-to-End Pipeline', icon: Workflow },
              { id: 'layers', label: 'Layered Architecture', icon: Layers },
              { id: 'dataflow', label: 'Data Flow & Math', icon: Cpu },
              { id: 'techstack', label: 'Technology Stack', icon: Code2 },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center gap-1.5 px-3 sm:px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                      : 'text-blue-900/70 hover:text-blue-950 hover:bg-blue-100/60'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* VIEW 1: END-TO-END PIPELINE DIAGRAM                                       */}
      {/* ========================================================================= */}
      {activeTab === 'blueprint' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Visual Interactive Pipeline Canvas */}
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 shadow-xl shadow-blue-900/5 space-y-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-blue-100 pb-4">
              <div>
                <h2 className="text-lg font-extrabold text-blue-950 flex items-center gap-2">
                  <Workflow className="h-5 w-5 text-blue-600" />
                  <span>Interactive System Flow Blueprint</span>
                </h2>
                <p className="text-xs text-blue-900/70 mt-0.5">
                  Click any node in the pipeline below to inspect its inputs, outputs, algorithms, and latency metrics:
                </p>
              </div>

              <div className="flex items-center gap-2 text-xs font-semibold text-blue-800 bg-blue-50 px-3 py-1.5 rounded-xl border border-blue-200">
                <Activity className="h-4 w-4 text-emerald-600 animate-pulse" />
                <span>Total Pipeline Latency: ~480ms</span>
              </div>
            </div>

            {/* Pipeline Stage Nodes */}
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { id: 'client_ui', num: '01', title: 'Client UI & Ext', subtitle: 'User Web Input', icon: Globe, color: 'border-sky-300 bg-sky-50/60' },
                { id: 'url_parser', num: '02', title: 'URL Parser', subtitle: '24 Academic Cues', icon: FileCode2, color: 'border-blue-300 bg-blue-50/60' },
                { id: 'svm_engine', num: '03', title: 'SVM Core ML', subtitle: 'RBF / Linear Kernel', icon: Cpu, color: 'border-indigo-300 bg-indigo-50/60' },
                { id: 'threat_intel', num: '04', title: 'Threat Feeds', subtitle: 'WHOIS & DNSSEC', icon: Radio, color: 'border-cyan-300 bg-cyan-50/60' },
                { id: 'gemini_xai', num: '05', title: 'Gemini XAI', subtitle: 'Plain English SOC', icon: Sparkles, color: 'border-purple-300 bg-purple-50/60' },
                { id: 'firebase_db', num: '06', title: 'Firestore DB', subtitle: 'Persistence & Alerts', icon: Database, color: 'border-amber-300 bg-amber-50/60' },
              ].map((step) => {
                const Icon = step.icon;
                const isSelected = selectedNodeId === step.id;
                return (
                  <button
                    key={step.id}
                    onClick={() => setSelectedNodeId(step.id)}
                    className={`relative p-4 rounded-2xl border text-left transition-all duration-200 cursor-pointer flex flex-col justify-between group ${
                      isSelected
                        ? 'bg-blue-600 text-white border-blue-600 shadow-lg shadow-blue-600/30 scale-[1.03]'
                        : 'bg-white hover:bg-blue-50/50 border-blue-100 hover:border-blue-300 text-blue-950'
                    }`}
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                            isSelected ? 'bg-white/20 text-white' : 'bg-blue-100 text-blue-800'
                          }`}
                        >
                          Stage {step.num}
                        </span>
                        <Icon className={`h-4 w-4 ${isSelected ? 'text-white' : 'text-blue-600'}`} />
                      </div>

                      <div>
                        <h4 className={`text-xs font-extrabold ${isSelected ? 'text-white' : 'text-blue-950'}`}>
                          {step.title}
                        </h4>
                        <p className={`text-[11px] mt-0.5 ${isSelected ? 'text-blue-100' : 'text-blue-800/70'}`}>
                          {step.subtitle}
                        </p>
                      </div>
                    </div>

                    <div className="mt-3 pt-2 border-t border-current/10 flex items-center justify-between text-[10px] font-bold">
                      <span>{isSelected ? 'Active Selection' : 'Inspect'}</span>
                      <ChevronRight className="h-3 w-3" />
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Selected Node Detailed Inspector */}
            <div className="rounded-2xl bg-blue-50/60 border border-blue-200 p-6 space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-blue-200/80 pb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-blue-600 text-white shadow-md shadow-blue-600/20">
                    <Server className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-base font-extrabold text-blue-950">{selectedNode.name}</h3>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                        {selectedNode.status}
                      </span>
                    </div>
                    <p className="text-xs text-blue-900/70">{selectedNode.tag}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold px-3 py-1 rounded-xl bg-white text-blue-900 border border-blue-200 shadow-sm">
                    Latency: {selectedNode.latency}
                  </span>
                </div>
              </div>

              <p className="text-xs sm:text-sm text-blue-950 leading-relaxed">
                {selectedNode.description}
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                {/* Inputs */}
                <div className="p-4 rounded-xl bg-white border border-blue-100 space-y-2">
                  <span className="text-[11px] font-mono font-bold uppercase text-blue-700 flex items-center gap-1.5">
                    <ArrowRight className="h-3.5 w-3.5 text-blue-600" />
                    Input Data Contracts
                  </span>
                  <ul className="space-y-1 text-xs text-blue-950">
                    {selectedNode.inputs.map((inp, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-blue-500 font-bold">•</span>
                        <span>{inp}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Outputs */}
                <div className="p-4 rounded-xl bg-white border border-blue-100 space-y-2">
                  <span className="text-[11px] font-mono font-bold uppercase text-blue-700 flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                    Output Artifacts
                  </span>
                  <ul className="space-y-1 text-xs text-blue-950">
                    {selectedNode.outputs.map((out, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-emerald-500 font-bold">•</span>
                        <span>{out}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Security Role */}
                <div className="p-4 rounded-xl bg-white border border-blue-100 space-y-2">
                  <span className="text-[11px] font-mono font-bold uppercase text-blue-700 flex items-center gap-1.5">
                    <Shield className="h-3.5 w-3.5 text-indigo-600" />
                    Security & Trust Guard
                  </span>
                  <p className="text-xs text-blue-950 leading-relaxed">
                    {selectedNode.securityRole}
                  </p>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {selectedNode.techStack.map((tech, idx) => (
                      <span key={idx} className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* URL Safety Verification Philosophy */}
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
            <div className="space-y-1">
              <h2 className="text-lg font-extrabold text-blue-950 flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-blue-600" />
                <span>How Link Safety Is Determined from the URL</span>
              </h2>
              <p className="text-xs text-blue-900/70">
                The infrastructure strictly evaluates URLs using a 3-tier security model combining lexical structure, mathematical decision hyperplanes, and cryptographic trust:
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-5 rounded-2xl bg-blue-50/50 border border-blue-200 space-y-2">
                <div className="h-8 w-8 rounded-xl bg-blue-600 text-white font-bold text-xs flex items-center justify-center shadow-md shadow-blue-600/20">
                  1
                </div>
                <h3 className="text-sm font-extrabold text-blue-950">1. Lexical Anatomy & Syntax</h3>
                <p className="text-xs text-blue-900/80 leading-relaxed">
                  Extracts raw textual features: protocol validity (HTTPS), hostname length, character entropy, numeric IP presence, hyphens, and Punycode spoofing tricks (<code className="text-blue-900 font-mono text-[11px]">xn--</code>).
                </p>
              </div>

              <div className="p-5 rounded-2xl bg-blue-50/50 border border-blue-200 space-y-2">
                <div className="h-8 w-8 rounded-xl bg-indigo-600 text-white font-bold text-xs flex items-center justify-center shadow-md shadow-indigo-600/20">
                  2
                </div>
                <h3 className="text-sm font-extrabold text-blue-950">2. SVM Multidimensional Vector</h3>
                <p className="text-xs text-blue-900/80 leading-relaxed">
                  Maps extracted cues into a 24-dimensional Hilbert space. Evaluates the separating hyperplane: positive scores (<strong className="text-emerald-700">+1.0 to +5.0</strong>) represent verified legitimate space, while negative scores (<strong className="text-rose-700">-1.0 to -8.0</strong>) indicate malicious phishing.
                </p>
              </div>

              <div className="p-5 rounded-2xl bg-blue-50/50 border border-blue-200 space-y-2">
                <div className="h-8 w-8 rounded-xl bg-cyan-600 text-white font-bold text-xs flex items-center justify-center shadow-md shadow-cyan-600/20">
                  3
                </div>
                <h3 className="text-sm font-extrabold text-blue-950">3. Cryptographic & WHOIS Trust</h3>
                <p className="text-xs text-blue-900/80 leading-relaxed">
                  Cross-checks real-world trust telemetry: valid TLS encryption certificates (DigiCert, Let's Encrypt), domain age longevity (&gt;365 days vs &lt;30 days burner domains), and safe browsing blacklists.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW 2: LAYERED ARCHITECTURE                                              */}
      {/* ========================================================================= */}
      {activeTab === 'layers' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
            <div className="space-y-1">
              <h2 className="text-lg font-extrabold text-blue-950 flex items-center gap-2">
                <Layers className="h-5 w-5 text-blue-600" />
                <span>6-Tier Hierarchical Architecture Blueprint</span>
              </h2>
              <p className="text-xs text-blue-900/70">
                Detailed decomposition of the software stack from the frontend browser runtime to cloud database persistence:
              </p>
            </div>

            <div className="space-y-3">
              {[
                {
                  tier: 'Tier 1: Presentation & Client Runtime',
                  tech: 'React 18 + Vite SPA + Tailwind CSS + Lucide Icons',
                  desc: 'Provides instant UI rendering with Dual-View modes ("Easy View" for general users, "Cyber Pro" for SOC analysts), responsive Link Safety Simulator, and real-time alerts badge stream.',
                  color: 'border-l-4 border-l-sky-500 bg-sky-50/40',
                },
                {
                  tier: 'Tier 2: Express Server & API Proxy Gateway',
                  tech: 'Node.js Express + TSX Runtime (Port 3000)',
                  desc: 'Handles /api/analyze routing, environment secret management (Gemini API keys kept strictly server-side), CORS security policies, and payload sanitization.',
                  color: 'border-l-4 border-l-blue-600 bg-blue-50/40',
                },
                {
                  tier: 'Tier 3: 24-Feature Lexical Extraction Engine',
                  tech: 'WHATWG URL Standard + Punycode Unicode Engine',
                  desc: 'Translates raw URL strings into 24 distinct academic features (SSL validity, domain age, hyphen injection, subdomain depth, token injection, character distribution).',
                  color: 'border-l-4 border-l-indigo-600 bg-indigo-50/40',
                },
                {
                  tier: 'Tier 4: Dual-Kernel Support Vector Machine (SVM)',
                  tech: 'Custom RBF Gaussian Kernel + Linear Hyperplane Math Matrix',
                  desc: 'Computes hyperplanes f(x) with Lagrange multipliers α, bias b = -0.42, soft-margin regularization C = 1.25, and Platt scaling probability calibration.',
                  color: 'border-l-4 border-l-purple-600 bg-purple-50/40',
                },
                {
                  tier: 'Tier 5: Explainable AI (XAI) & SOC Intelligence',
                  tech: 'Google Gemini 2.5 Flash (@google/genai SDK)',
                  desc: 'Synthesizes mathematical decision boundaries into natural language explanations, MITRE ATT&CK tactical techniques, and step-by-step mitigation checklists.',
                  color: 'border-l-4 border-l-violet-600 bg-violet-50/40',
                },
                {
                  tier: 'Tier 6: Persistence & Cloud Synchronization',
                  tech: 'Google Firebase Cloud Firestore + Firebase Authentication',
                  desc: 'Provides real-time synchronized persistence for historical scan records, incident response security alerts, watchlist collections, and user authentication.',
                  color: 'border-l-4 border-l-amber-500 bg-amber-50/40',
                },
              ].map((layer, idx) => (
                <div key={idx} className={`p-5 rounded-2xl border border-blue-100 ${layer.color} space-y-1.5`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <h3 className="text-sm font-extrabold text-blue-950">{layer.tier}</h3>
                    <span className="text-[11px] font-mono font-bold text-blue-700 bg-white px-2.5 py-0.5 rounded-full border border-blue-200 shrink-0">
                      {layer.tech}
                    </span>
                  </div>
                  <p className="text-xs text-blue-900/80 leading-relaxed">
                    {layer.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW 3: DATA FLOW & MATHEMATICS                                           */}
      {/* ========================================================================= */}
      {activeTab === 'dataflow' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
            <div className="space-y-1">
              <h2 className="text-lg font-extrabold text-blue-950 flex items-center gap-2">
                <Cpu className="h-5 w-5 text-blue-600" />
                <span>Mathematical Formulation of the SVM Decision Engine</span>
              </h2>
              <p className="text-xs text-blue-900/70">
                How the mathematical engine evaluates 24 feature dimensions to partition safe websites from phishing attacks:
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-5 rounded-2xl bg-blue-50/60 border border-blue-200 space-y-3 font-mono text-xs">
                <span className="text-blue-800 font-extrabold block text-xs">// 1. Primary SVM Decision Hyperplane</span>
                <div className="p-3 rounded-xl bg-white border border-blue-200 text-blue-950 font-bold text-sm">
                  f(x) = sgn( ∑ [ αᵢ · yᵢ · K(xᵢ, x) ] + b )
                </div>
                <p className="text-[11px] text-blue-900/80 leading-relaxed font-sans">
                  Where <code className="text-blue-900 font-bold">x</code> is the 24-feature vector extracted from the URL, <code className="text-blue-900 font-bold">αᵢ</code> are optimal Lagrange multipliers, <code className="text-blue-900 font-bold">yᵢ ∈ {'{-1, +1}'}</code> are training labels, and <code className="text-blue-900 font-bold">b = -0.42</code> is the hyperplane bias intercept.
                </p>
              </div>

              <div className="p-5 rounded-2xl bg-blue-50/60 border border-blue-200 space-y-3 font-mono text-xs">
                <span className="text-indigo-800 font-extrabold block text-xs">// 2. Radial Basis Function (RBF) Gaussian Kernel</span>
                <div className="p-3 rounded-xl bg-white border border-blue-200 text-blue-950 font-bold text-sm">
                  K(x, z) = exp( -γ · ||x - z||² )
                </div>
                <p className="text-[11px] text-blue-900/80 leading-relaxed font-sans">
                  Maps non-linear feature interactions into infinite-dimensional Hilbert space. With <code className="text-indigo-900 font-bold">γ = 0.045</code> and regularization <code className="text-indigo-900 font-bold">C = 1.25</code>, preventing overfitting to zero-day domain variations.
                </p>
              </div>
            </div>

            {/* JSON Payload Schema Explorer */}
            <div className="p-5 rounded-2xl bg-blue-950 text-white space-y-3">
              <div className="flex items-center justify-between border-b border-blue-800 pb-3">
                <div className="flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-sky-400" />
                  <span className="text-xs font-mono font-bold text-sky-300">Data Contract / Pipeline Payload Schema</span>
                </div>
                <button
                  onClick={handleCopyPayload}
                  className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-blue-800 hover:bg-blue-700 text-xs font-semibold text-white transition-colors cursor-pointer"
                >
                  {copiedSchema ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedSchema ? 'Copied JSON!' : 'Copy Schema'}</span>
                </button>
              </div>

              <pre className="text-xs font-mono text-blue-200 overflow-x-auto p-2 bg-blue-900/40 rounded-xl leading-relaxed">
                {JSON.stringify(samplePipelinePayload, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW 4: TECHNOLOGY STACK SPECIFICATIONS                                   */}
      {/* ========================================================================= */}
      {activeTab === 'techstack' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
            <div className="space-y-1">
              <h2 className="text-lg font-extrabold text-blue-950 flex items-center gap-2">
                <Code2 className="h-5 w-5 text-blue-600" />
                <span>Production Technology Stack & Dependencies</span>
              </h2>
              <p className="text-xs text-blue-900/70">
                Verified modular components running within the Cloud Run container runtime:
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {[
                { title: 'Frontend Framework', tech: 'React 18.3 + TypeScript', desc: 'Type-safe single-page application with modular state management and custom hooks.' },
                { title: 'Styling & UI Design', tech: 'Tailwind CSS v4', desc: 'Clean white background canvas with high-contrast royal blue typography and responsive grid hierarchy.' },
                { title: 'Machine Learning Engine', tech: 'Dual-Kernel SVM (RBF/Linear)', desc: 'Pre-trained support vector machine utilizing 24 academic UCI phishing features with Platt scaling.' },
                { title: 'Explainable AI (XAI)', tech: 'Gemini 2.5 Flash SDK', desc: 'Server-side Generative AI integration for natural language threat synthesis and SOC recommendations.' },
                { title: 'Cloud Database & Auth', tech: 'Google Firebase Firestore', desc: 'Real-time database collections for scan logs, security alerts, and analyst watchlists.' },
                { title: 'Data Visualization', tech: 'Recharts (D3.js)', desc: 'SHAP waterfall feature impact charts, risk gauges, and mathematical margin plots.' },
              ].map((item, idx) => (
                <div key={idx} className="p-5 rounded-2xl bg-blue-50/50 border border-blue-100 space-y-2 hover:border-blue-300 transition-colors">
                  <span className="text-[11px] font-mono uppercase font-bold text-blue-600 block">{item.title}</span>
                  <h4 className="text-sm font-extrabold text-blue-950">{item.tech}</h4>
                  <p className="text-xs text-blue-900/80 leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
