export type ThreatLevel = 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'Safe' | 'Low' | 'Suspicious' | 'Phishing' | 'INACTIVE' | 'PARKED' | 'NOT_FOUND';
export type ScanVerdict = 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'INACTIVE' | 'PARKED' | 'NOT_FOUND';

export interface ExtractedFeatureItem {
  id: string;
  name: string;
  category: 'url_structure' | 'domain_ssl' | 'heuristics_content' | 'threat_reputation';
  value: string | number | boolean;
  score: -1 | 0 | 1; // -1: Phishing/Malicious, 0: Unrated/Unverified/Suspicious, 1: Verified Legitimate
  weight: number; // SVM feature weight
  impact: number; // SHAP / contribution to decision
  description: string;
  rationale: string;
  verificationStatus?: 'verified' | 'heuristic' | 'unverified';
}

export interface SvmEvaluation {
  isPhishing: boolean;
  prediction: -1 | 1; // -1: Phishing, 1: Legitimate
  confidence: number; // 0-100%
  decisionValue: number; // f(x)
  hyperplaneDistance: number;
  margin: number;
  kernelType: 'RBF (Radial Basis Function)' | 'Linear' | 'Polynomial';
  gamma: number;
  cParameter: number;
  supportVectorsUsed: number;
  totalSupportVectors: number;
  linearScore: number;
  rbfScore: number;
  confusionMatrix: {
    truePositive: number;
    falsePositive: number;
    trueNegative: number;
    falseNegative: number;
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
  };
}

export interface DomainInfo {
  domain: string;
  hostname: string;
  ipAddress: string;
  country: string;
  countryCode: string;
  registrar: string;
  creationDate: string;
  domainAgeDays: number | null;
  domainAgeFormatted: string;
  expiryDate: string;
  nameservers: string[];
  dnsRecords: {
    type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME';
    value: string;
  }[];
  ssl: {
    hasSsl: boolean;
    issuer: string;
    valid: boolean;
    protocol: string;
    daysRemaining?: number | null;
  };
  tld: string;
  entropy: number;
  hasPunycode: boolean;
  punycodeDecoded?: string;
  isVerifiedDomain: boolean;
  verificationStatus: 'Verified Authority' | 'Unverified / Unknown Domain' | 'High-Risk Threat Domain' | 'Non-Existent Domain' | 'Parked / Inactive Domain';
  domainExists?: boolean;
  isParked?: boolean;
  httpActive?: boolean;
  websiteStatus?: 'ACTIVE' | 'PARKED' | 'NON_EXISTENT' | 'UNREACHABLE';
  statusDetails?: string;
}

export type ThreatServiceStatus = 'Clean' | 'Flagged' | 'Unrated' | 'Unavailable' | 'Not Configured' | 'Not Indexed' | 'Not Checked';

export interface ThreatIntelligence {
  isBlacklisted: boolean;
  overallReputation: 'Clean' | 'Suspicious' | 'High Risk Malicious' | 'Unrated' | 'Unavailable' | 'Not Configured';
  feedsChecked: number;
  feedsFlagged: number;
  threatOverrideTriggered?: boolean;
  googleSafeBrowsing?: {
    status: ThreatServiceStatus;
    details?: string;
    lastUpdated?: string;
  };
  virusTotal?: {
    status: ThreatServiceStatus;
    details?: string;
    detectionsCount?: number;
    totalEngines?: number;
    lastUpdated?: string;
  };
  sources: {
    name: string;
    category: string;
    status: ThreatServiceStatus;
    lastUpdated: string;
    details?: string;
    isLiveLookup?: boolean;
  }[];
  detectedAttackTypes: string[];
  targetedBrand?: string;
}

export interface ExplainableAiReport {
  summary: string;
  verdictReasoning: string;
  primaryRiskFactors: string[];
  positiveSecurityIndicators: string[];
  attackVectorType: string;
  suspectedBrandImpersonation: string | null;
  tacticsTechniques: string[];
  actionableRecommendations: string[];
  technicalBreakdown: string;
  generatedByAi: boolean;
}

export interface ScanResult {
  id: string;
  userId?: string;
  url: string;
  domain: string;
  timestamp: number;
  isPhishing: boolean;
  riskScore: number; // 0 (Safe) to 100 (Phishing)
  threatLevel: ThreatLevel;
  verdict: ScanVerdict;
  confidence: number;
  svm: SvmEvaluation;
  features: Record<string, ExtractedFeatureItem>;
  domainInfo: DomainInfo;
  threatIntel: ThreatIntelligence;
  xai: ExplainableAiReport;
  bookmarked?: boolean;
  analysisMode?: 'server' | 'local_fallback';
  analysisNotice?: string;
  websiteStatus?: {
    domainExists: boolean;
    isParked: boolean;
    httpActive: boolean;
    status: 'ACTIVE' | 'PARKED' | 'NON_EXISTENT' | 'UNREACHABLE';
    details: string;
  };
}

export interface SecurityAlert {
  id: string;
  userId: string;
  scanId?: string;
  url: string;
  domain: string;
  threatType: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'Active' | 'Investigating' | 'Blocked' | 'False_Positive' | 'Resolved';
  riskScore: number;
  notes?: string;
  createdAt: number;
  resolvedAt?: number;
}

export interface WatchlistItem {
  id: string;
  userId: string;
  type: 'whitelist' | 'blacklist';
  domainOrUrl: string;
  reason: string;
  addedAt: number;
}

export interface UserProfile {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL?: string;
  isAnonymous?: boolean;
  role?: 'analyst' | 'admin' | 'user' | string;
  createdAt?: string | number;
}

export interface SafeBrowserSyncConfig {
  autoSync: boolean;
  syncInterval: 'realtime' | '15m' | '1h' | '6h' | '24h';
  syncGoogleSafeBrowsing: boolean;
  syncPhishTank: boolean;
  syncOpenPhish: boolean;
  syncSvmWeights: boolean;
  syncCloudWatchlist: boolean;
  protectionMode: 'strict' | 'standard' | 'diagnostic';
  offlineLocalHashMatching: boolean;
  lastSyncedAt: number;
  totalSignatures: number;
  dbVersion: string;
}

export interface SyncFeedItem {
  id: string;
  name: string;
  provider: string;
  category: 'threat_feed' | 'ml_weights' | 'hash_prefixes' | 'custom_rules';
  status: 'Synced' | 'Syncing' | 'Pending' | 'Offline';
  signaturesCount: number;
  latencyMs: number;
  lastUpdated: string;
  description: string;
}

export interface SyncLogEntry {
  id: string;
  timestamp: number;
  type: 'Full Sync' | 'Delta Update' | 'Model Re-weight' | 'Watchlist Sync' | 'Hash Prefix Flush';
  feedName: string;
  recordsDelta: number;
  status: 'success' | 'warning' | 'failed';
  durationMs: number;
  details: string;
}
