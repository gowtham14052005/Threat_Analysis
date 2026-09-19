import React, { useState } from 'react';
import {
  Radio,
  ExternalLink,
  ShieldAlert,
  Globe,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Server,
  Activity
} from 'lucide-react';
import { ScanResult } from '../types';

interface ThreatFeedsProps {
  onScanUrl: (url: string) => void;
}

interface ThreatFeedEntry {
  id: string;
  url: string;
  domain: string;
  source: 'PhishTank' | 'OpenPhish' | 'URLHaus' | 'APWG' | 'CertTelemetry';
  targetBrand: string;
  threatType: string;
  ip: string;
  country: string;
  reportedAgo: string;
  riskScore: number;
}

const LIVE_FEEDS_DATA: ThreatFeedEntry[] = [
  {
    id: 'tf-1',
    url: 'http://paypa1-security-verification.xyz/login/verify.php',
    domain: 'paypa1-security-verification.xyz',
    source: 'PhishTank',
    targetBrand: 'PayPal',
    threatType: 'Credential Harvesting',
    ip: '185.220.101.5',
    country: 'Seychelles',
    reportedAgo: '4 mins ago',
    riskScore: 96,
  },
  {
    id: 'tf-2',
    url: 'http://185.220.101.42:8080/chase-online/auth.html',
    domain: '185.220.101.42:8080',
    source: 'URLHaus',
    targetBrand: 'Chase Bank',
    threatType: 'Bypassing DNS (Raw IP)',
    ip: '185.220.101.42',
    country: 'Russia',
    reportedAgo: '12 mins ago',
    riskScore: 92,
  },
  {
    id: 'tf-3',
    url: 'https://accounts-google-drive-share.top/auth/signin',
    domain: 'accounts-google-drive-share.top',
    source: 'OpenPhish',
    targetBrand: 'Google Workspace',
    threatType: 'OAuth Consent Phishing',
    ip: '104.21.55.2',
    country: 'United States',
    reportedAgo: '28 mins ago',
    riskScore: 94,
  },
  {
    id: 'tf-4',
    url: 'http://netflix-billing-update-account.com/renew-subscription',
    domain: 'netflix-billing-update-account.com',
    source: 'APWG',
    targetBrand: 'Netflix',
    threatType: 'Credit Card Skimming',
    ip: '45.142.214.19',
    country: 'Bulgaria',
    reportedAgo: '45 mins ago',
    riskScore: 89,
  },
  {
    id: 'tf-5',
    url: 'https://appleid-apple-support-recover.info/login',
    domain: 'appleid-apple-support-recover.info',
    source: 'PhishTank',
    targetBrand: 'Apple ID',
    threatType: '2FA Bypass Phishing',
    ip: '91.240.118.88',
    country: 'Panama',
    reportedAgo: '1 hour ago',
    riskScore: 95,
  },
  {
    id: 'tf-6',
    url: 'http://meta-business-suite-appeals-center.vip/verify',
    domain: 'meta-business-suite-appeals-center.vip',
    source: 'CertTelemetry',
    targetBrand: 'Meta / Facebook',
    threatType: 'Account Takeover Lure',
    ip: '194.26.29.112',
    country: 'Cyprus',
    reportedAgo: '1.5 hours ago',
    riskScore: 91,
  },
];

export const ThreatFeeds: React.FC<ThreatFeedsProps> = ({ onScanUrl }) => {
  const [feeds, setFeeds] = useState<ThreatFeedEntry[]>(LIVE_FEEDS_DATA);
  const [selectedSource, setSelectedSource] = useState<string>('all');
  const [search, setSearch] = useState<string>('');
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
    }, 800);
  };

  const filteredFeeds = feeds.filter((item) => {
    const matchesSource = selectedSource === 'all' || item.source === selectedSource;
    const matchesSearch =
      search === '' ||
      item.domain.toLowerCase().includes(search.toLowerCase()) ||
      item.targetBrand.toLowerCase().includes(search.toLowerCase()) ||
      item.threatType.toLowerCase().includes(search.toLowerCase());
    return matchesSource && matchesSearch;
  });

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-mono font-bold mb-2">
            <Radio className="h-3.5 w-3.5 text-emerald-600 animate-pulse" />
            <span>Global Threat Intelligence Feeds</span>
          </div>
          <h1 className="text-3xl font-extrabold text-blue-950">
            Live Phishing <span className="text-blue-600">Radar & Telemetry</span>
          </h1>
          <p className="text-xs sm:text-sm text-blue-900/70">
            Real-time ingested indicators of compromise (IOCs) from PhishTank, OpenPhish, and global honeypots.
          </p>
        </div>

        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white hover:bg-blue-50 border border-blue-200 text-xs font-bold text-blue-900 transition-colors shadow-xs self-start sm:self-auto cursor-pointer"
        >
          <RefreshCw className={`h-3.5 w-3.5 text-blue-600 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>{isRefreshing ? 'Syncing Feeds...' : 'Sync Active Feeds'}</span>
        </button>
      </div>

      {/* Threat Sources Status Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { name: 'PhishTank Community', status: 'Live 99.8%', count: '14,280' },
          { name: 'OpenPhish AI Stream', status: 'Live 100%', count: '8,950' },
          { name: 'URLHaus Abuse.ch', status: 'Live 99.9%', count: '22,410' },
          { name: 'APWG Global Data', status: 'Live 99.5%', count: '17,120' },
          { name: 'PhishGuard SVM Trap', status: 'Active 100%', count: '4,680' },
        ].map((src) => (
          <div key={src.name} className="p-4 rounded-2xl bg-white border border-blue-100 space-y-1 shadow-xs">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold text-blue-900/70">{src.name}</span>
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
            </div>
            <div className="text-base font-mono font-black text-blue-950">{src.count}</div>
            <div className="text-[10px] text-emerald-700 font-mono font-bold">{src.status}</div>
          </div>
        ))}
      </div>

      {/* Target Breakdown Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xs">
          <span className="text-xs font-extrabold text-blue-950">Financial & Banking</span>
          <div className="text-2xl font-mono font-black text-blue-600">42%</div>
          <div className="h-2 rounded-full bg-blue-100 overflow-hidden">
            <div className="h-full bg-blue-600 rounded-full" style={{ width: '42%' }} />
          </div>
          <span className="text-[10px] text-blue-900/60 font-medium">PayPal, Chase, Wells Fargo, BoA</span>
        </div>

        <div className="p-5 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xs">
          <span className="text-xs font-extrabold text-blue-950">Cloud & Enterprise</span>
          <div className="text-2xl font-mono font-black text-indigo-600">28%</div>
          <div className="h-2 rounded-full bg-blue-100 overflow-hidden">
            <div className="h-full bg-indigo-600 rounded-full" style={{ width: '28%' }} />
          </div>
          <span className="text-[10px] text-blue-900/60 font-medium">Microsoft 365, Google Workspace, AWS</span>
        </div>

        <div className="p-5 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xs">
          <span className="text-xs font-extrabold text-blue-950">Social Media & Crypto</span>
          <div className="text-2xl font-mono font-black text-purple-600">16%</div>
          <div className="h-2 rounded-full bg-blue-100 overflow-hidden">
            <div className="h-full bg-purple-600 rounded-full" style={{ width: '16%' }} />
          </div>
          <span className="text-[10px] text-blue-900/60 font-medium">Meta, Binance, MetaMask, Discord</span>
        </div>

        <div className="p-5 rounded-3xl bg-white border border-blue-100 space-y-2 shadow-xs">
          <span className="text-xs font-extrabold text-blue-950">Postal & Delivery</span>
          <div className="text-2xl font-mono font-black text-rose-600">14%</div>
          <div className="h-2 rounded-full bg-blue-100 overflow-hidden">
            <div className="h-full bg-rose-600 rounded-full" style={{ width: '14%' }} />
          </div>
          <span className="text-[10px] text-blue-900/60 font-medium">DHL, USPS, FedEx package lures</span>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 rounded-2xl bg-white border border-blue-100 shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          {['all', 'PhishTank', 'OpenPhish', 'URLHaus', 'APWG'].map((st) => (
            <button
              key={st}
              onClick={() => setSelectedSource(st)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-colors cursor-pointer ${
                selectedSource === st
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-blue-900/70 hover:text-blue-950 bg-blue-50'
              }`}
            >
              {st === 'all' ? 'All Feeds' : st}
            </button>
          ))}
        </div>

        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by target brand / domain..."
          className="px-3.5 py-1.5 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600 font-mono"
        />
      </div>

      {/* Live Stream Table */}
      <div className="overflow-hidden rounded-3xl bg-white border border-blue-100 shadow-xl shadow-blue-900/5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-blue-50/80 border-b border-blue-100 font-mono text-blue-900 uppercase text-[10px]">
              <tr>
                <th className="px-4 py-3.5">Ingested Phishing Target</th>
                <th className="px-4 py-3.5">Impersonated Brand</th>
                <th className="px-4 py-3.5">Threat Feed Source</th>
                <th className="px-4 py-3.5">Hosting IP / Geo</th>
                <th className="px-4 py-3.5">Reported</th>
                <th className="px-4 py-3.5 text-right">Deep SVM Scan</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-blue-50">
              {filteredFeeds.map((feed) => (
                <tr key={feed.id} className="hover:bg-blue-50/40 transition-colors">
                  <td className="px-4 py-3.5 font-mono">
                    <div className="font-extrabold text-rose-600">{feed.domain}</div>
                    <div className="text-[11px] text-blue-900/70 truncate max-w-xs">{feed.url}</div>
                  </td>
                  <td className="px-4 py-3.5 font-bold text-blue-950">
                    <span className="px-2.5 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-900 text-xs">
                      {feed.targetBrand}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 font-mono text-blue-900">
                    <span className="text-[11px] font-extrabold text-indigo-600">{feed.source}</span>
                  </td>
                  <td className="px-4 py-3.5 text-blue-900 font-mono text-[11px]">
                    <div className="font-bold">{feed.ip}</div>
                    <div className="text-blue-900/60 font-sans text-[10px]">{feed.country}</div>
                  </td>
                  <td className="px-4 py-3.5 text-blue-900/70 font-mono text-[11px]">
                    {feed.reportedAgo}
                  </td>
                  <td className="px-4 py-3.5 text-right">
                    <button
                      onClick={() => onScanUrl(feed.url)}
                      className="px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition-all cursor-pointer"
                    >
                      Inspect URL →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
