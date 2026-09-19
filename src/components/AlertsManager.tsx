import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Clock,
  Filter,
  Plus,
  Search,
  ExternalLink,
  MessageSquare,
  ChevronRight,
  Sparkles,
  AlertCircle,
  Database
} from 'lucide-react';
import { SecurityAlert, UserProfile } from '../types';
import { db, updateAlertStatusInFirestore, createAlertInFirestore } from '../lib/firebase';
import { collection, onSnapshot, query, orderBy, limit } from 'firebase/firestore';

interface AlertsManagerProps {
  user: UserProfile | null;
  onOpenScan?: (url: string) => void;
}

const INITIAL_DEMO_ALERTS: SecurityAlert[] = [
  {
    id: 'alert-demo-1',
    userId: 'system',
    url: 'http://paypa1-security-verification.xyz/login/verify.php',
    domain: 'paypa1-security-verification.xyz',
    threatType: 'Credential Harvesting & Brand Impersonation',
    severity: 'Critical',
    status: 'Active',
    riskScore: 96,
    notes: 'SVM Classifier flagged typo-squatting with 98.4% confidence. PhishTank feed confirmed active threat.',
    createdAt: Date.now() - 1000 * 60 * 15,
  },
  {
    id: 'alert-demo-2',
    userId: 'system',
    url: 'http://185.220.101.42:8080/chase-online/auth.html',
    domain: '185.220.101.42:8080',
    threatType: 'Raw IP Bank Login (Bypassing DNS)',
    severity: 'High',
    status: 'Investigating',
    riskScore: 92,
    notes: 'Direct IP hosting on non-standard port 8080 simulating Chase corporate credentials.',
    createdAt: Date.now() - 1000 * 60 * 45,
  },
  {
    id: 'alert-demo-3',
    userId: 'system',
    url: 'https://accounts-google-drive-share.top/auth/signin',
    domain: 'accounts-google-drive-share.top',
    threatType: 'OAuth Phishing Lure',
    severity: 'Critical',
    status: 'Blocked',
    riskScore: 94,
    notes: 'Domain blocked at edge firewall. DNS sinkhole applied.',
    createdAt: Date.now() - 1000 * 60 * 120,
    resolvedAt: Date.now() - 1000 * 60 * 30,
  },
];

export const AlertsManager: React.FC<AlertsManagerProps> = ({ user, onOpenScan }) => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_DEMO_ALERTS);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [noteInput, setNoteInput] = useState<string>('');
  const [isCreatingAlert, setIsCreatingAlert] = useState<boolean>(false);
  const [newUrl, setNewUrl] = useState<string>('');
  const [newThreatType, setNewThreatType] = useState<string>('Credential Harvesting');
  const [newSeverity, setNewSeverity] = useState<SecurityAlert['severity']>('Critical');

  // Real-time Firestore Subscription
  useEffect(() => {
    try {
      const q = query(collection(db, 'alerts'), orderBy('createdAt', 'desc'), limit(50));
      const unsubscribe = onSnapshot(
        q,
        (snapshot) => {
          if (!snapshot.empty) {
            const fetched: SecurityAlert[] = snapshot.docs.map((doc) => ({
              id: doc.id,
              ...doc.data(),
            })) as SecurityAlert[];
            setAlerts(fetched);
          }
        },
        (err) => {
          console.warn('Firestore alerts subscription notice:', err);
        }
      );
      return () => unsubscribe();
    } catch (e) {
      console.warn('Firestore listener setup failed:', e);
    }
  }, []);

  const handleUpdateStatus = async (alertId: string, status: SecurityAlert['status']) => {
    // Optimistic local update
    setAlerts((prev) =>
      prev.map((a) =>
        a.id === alertId ? { ...a, status, resolvedAt: status === 'Resolved' ? Date.now() : a.resolvedAt } : a
      )
    );
    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert({ ...selectedAlert, status });
    }
    // Sync to Firestore
    await updateAlertStatusInFirestore(alertId, status, noteInput || undefined);
  };

  const handleAddNote = async () => {
    if (!selectedAlert || !noteInput.trim()) return;
    const updatedNotes = (selectedAlert.notes ? selectedAlert.notes + '\n\n' : '') + `[${new Date().toLocaleTimeString()}] ` + noteInput.trim();
    setAlerts((prev) =>
      prev.map((a) => (a.id === selectedAlert.id ? { ...a, notes: updatedNotes } : a))
    );
    setSelectedAlert({ ...selectedAlert, notes: updatedNotes });
    setNoteInput('');
    await updateAlertStatusInFirestore(selectedAlert.id, selectedAlert.status, updatedNotes);
  };

  const handleCreateManualAlert = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl.trim()) return;

    try {
      const domain = newUrl.replace(/https?:\/\//, '').split('/')[0];
      const newAlertData: Omit<SecurityAlert, 'id' | 'createdAt'> = {
        userId: user?.uid || 'analyst',
        url: newUrl.startsWith('http') ? newUrl : `https://${newUrl}`,
        domain,
        threatType: newThreatType,
        severity: newSeverity,
        status: 'Active',
        riskScore: newSeverity === 'Critical' ? 95 : (newSeverity === 'High' ? 80 : 60),
        notes: `Manual incident logged by security analyst (${user?.email || 'analyst'}).`,
      };

      const newId = await createAlertInFirestore(newAlertData);
      setAlerts((prev) => [
        { id: newId, ...newAlertData, createdAt: Date.now() },
        ...prev,
      ]);
      setNewUrl('');
      setIsCreatingAlert(false);
    } catch (err) {
      console.error('Failed to create manual alert:', err);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    const matchesStatus = filterStatus === 'all' || a.status === filterStatus;
    const matchesSeverity = filterSeverity === 'all' || a.severity === filterSeverity;
    const matchesSearch =
      searchQuery === '' ||
      a.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.threatType.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSeverity && matchesSearch;
  });

  const activeCount = alerts.filter((a) => a.status === 'Active').length;
  const criticalCount = alerts.filter((a) => a.severity === 'Critical').length;
  const blockedCount = alerts.filter((a) => a.status === 'Blocked' || a.status === 'Resolved').length;

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-50 border border-rose-200 text-rose-700 text-xs font-mono font-bold mb-2">
            <ShieldAlert className="h-3.5 w-3.5 text-rose-600" />
            <span>Incident Response & Triage Center</span>
          </div>
          <h1 className="text-3xl font-extrabold text-blue-950">
            Security <span className="text-rose-600">Alerts & Threat Triage</span>
          </h1>
          <p className="text-xs sm:text-sm text-blue-900/70">
            Real-time incident response management powered by Firebase Firestore live synchronization.
          </p>
        </div>

        <button
          onClick={() => setIsCreatingAlert(!isCreatingAlert)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-2xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-md shadow-blue-600/20 transition-all self-start sm:self-auto cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          <span>Log Security Incident</span>
        </button>
      </div>

      {/* Manual Alert Modal / Drawer */}
      {isCreatingAlert && (
        <form
          onSubmit={handleCreateManualAlert}
          className="p-6 rounded-3xl bg-white border border-blue-200 shadow-xl space-y-4 animate-in slide-in-from-top-2"
        >
          <div className="flex items-center justify-between border-b border-blue-100 pb-3">
            <h3 className="text-sm font-extrabold text-blue-950 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-blue-600" />
              <span>Create Manual Security Incident Alert</span>
            </h3>
            <button
              type="button"
              onClick={() => setIsCreatingAlert(false)}
              className="text-xs text-blue-900/60 hover:text-blue-950 font-bold cursor-pointer"
            >
              Cancel
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="sm:col-span-2 space-y-1">
              <label className="text-xs text-blue-950 font-bold">Target URL or Domain</label>
              <input
                type="text"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                placeholder="https://malicious-login-trap.xyz/verify"
                required
                className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs font-mono focus:outline-none focus:border-blue-600"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-blue-950 font-bold">Severity</label>
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value as any)}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs font-bold focus:outline-none focus:border-blue-600"
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>

            <div className="sm:col-span-3 space-y-1">
              <label className="text-xs text-blue-950 font-bold">Threat Vector / Attack Type</label>
              <input
                type="text"
                value={newThreatType}
                onChange={(e) => setNewThreatType(e.target.value)}
                placeholder="e.g. Credential Harvesting / Typo-Squatting"
                className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="submit"
              className="px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold shadow-md shadow-rose-600/20 transition-colors cursor-pointer"
            >
              Submit & Dispatch Alert
            </button>
          </div>
        </form>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-5 rounded-3xl bg-white border border-rose-200 space-y-1 shadow-xs">
          <span className="text-[10px] font-mono uppercase font-bold text-rose-700">Active Critical Incidents</span>
          <div className="text-2xl font-mono font-black text-rose-700">{criticalCount}</div>
          <p className="text-[11px] text-blue-900/70">Immediate remediation required</p>
        </div>

        <div className="p-5 rounded-3xl bg-white border border-amber-200 space-y-1 shadow-xs">
          <span className="text-[10px] font-mono uppercase font-bold text-amber-700">Open Triage Tickets</span>
          <div className="text-2xl font-mono font-black text-amber-700">{activeCount}</div>
          <p className="text-[11px] text-blue-900/70">Pending analyst review</p>
        </div>

        <div className="p-5 rounded-3xl bg-white border border-emerald-200 space-y-1 shadow-xs">
          <span className="text-[10px] font-mono uppercase font-bold text-emerald-700">Blocked & Resolved</span>
          <div className="text-2xl font-mono font-black text-emerald-700">{blockedCount}</div>
          <p className="text-[11px] text-blue-900/70">Firewall sinkhole applied</p>
        </div>

        <div className="p-5 rounded-3xl bg-white border border-blue-200 space-y-1 shadow-xs">
          <span className="text-[10px] font-mono uppercase font-bold text-blue-700">Firestore Realtime DB</span>
          <div className="flex items-center gap-2 mt-1 text-emerald-700 font-extrabold text-sm">
            <div className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
            <span>Synced Live</span>
          </div>
          <p className="text-[11px] text-blue-900/70">Instant multi-device streaming</p>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 rounded-2xl bg-white border border-blue-100 shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          {['all', 'Active', 'Investigating', 'Blocked', 'Resolved'].map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-colors cursor-pointer ${
                filterStatus === st
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-blue-900/70 hover:text-blue-950 bg-blue-50'
              }`}
            >
              {st === 'all' ? 'All Statuses' : st}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-3.5 py-1.5 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs font-bold focus:outline-none focus:border-blue-600"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search domain / URL..."
            className="px-3.5 py-1.5 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600 font-mono"
          />
        </div>
      </div>

      {/* Alerts Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Alerts List */}
        <div className="lg:col-span-2 space-y-3">
          {filteredAlerts.length === 0 ? (
            <div className="p-12 text-center rounded-3xl bg-white border border-blue-100 text-blue-900/60 space-y-2 shadow-xs">
              <ShieldCheck className="h-8 w-8 text-emerald-600 mx-auto" />
              <p className="text-sm font-bold text-blue-950">No matching security alerts found</p>
              <p className="text-xs">All monitored endpoints are currently safe.</p>
            </div>
          ) : (
            filteredAlerts.map((alert) => {
              const isSelected = selectedAlert?.id === alert.id;
              return (
                <div
                  key={alert.id}
                  onClick={() => setSelectedAlert(alert)}
                  className={`p-5 rounded-2xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-blue-50/80 border-blue-600 shadow-md'
                      : 'bg-white hover:bg-blue-50/40 border-blue-100 shadow-xs'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1.5 flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full ${
                            alert.severity === 'Critical'
                              ? 'bg-rose-100 text-rose-800 border border-rose-200'
                              : alert.severity === 'High'
                              ? 'bg-amber-100 text-amber-800 border border-amber-200'
                              : 'bg-blue-100 text-blue-800 border border-blue-200'
                          }`}
                        >
                          {alert.severity}
                        </span>

                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                            alert.status === 'Active'
                              ? 'bg-rose-50 text-rose-700 border border-rose-200'
                              : alert.status === 'Investigating'
                              ? 'bg-amber-50 text-amber-700 border border-amber-200'
                              : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          }`}
                        >
                          {alert.status}
                        </span>

                        <span className="text-[11px] text-blue-900/60 font-mono">
                          {new Date(alert.createdAt).toLocaleTimeString()}
                        </span>
                      </div>

                      <h4 className="text-sm font-extrabold text-blue-950 font-mono truncate">
                        {alert.domain}
                      </h4>

                      <p className="text-xs text-blue-900/75 font-medium">
                        {alert.threatType}
                      </p>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-xs font-mono font-black text-rose-600 block">
                        Risk: {alert.riskScore}%
                      </span>
                      <ChevronRight className={`h-4 w-4 text-blue-400 mt-2 ml-auto ${isSelected ? 'text-blue-600' : ''}`} />
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Selected Alert Triage Details */}
        <div className="rounded-3xl bg-white border border-blue-100 p-6 space-y-6 lg:sticky lg:top-24 h-fit shadow-xl shadow-blue-900/5">
          {selectedAlert ? (
            <div className="space-y-4 animate-in fade-in duration-200">
              <div className="border-b border-blue-100 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-blue-900/60 uppercase font-bold">Alert ID: {selectedAlert.id}</span>
                  <span className="text-xs font-extrabold text-rose-600">{selectedAlert.severity} Severity</span>
                </div>
                <h3 className="text-base font-extrabold text-blue-950 font-mono mt-1 break-all">
                  {selectedAlert.domain}
                </h3>
              </div>

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-blue-900/60 font-mono text-[11px] font-bold">Flagged URL:</span>
                  <p className="text-blue-950 font-mono break-all mt-0.5">{selectedAlert.url}</p>
                </div>

                <div>
                  <span className="text-blue-900/60 font-mono text-[11px] font-bold">Threat Classification:</span>
                  <p className="text-blue-950 font-bold mt-0.5">{selectedAlert.threatType}</p>
                </div>

                <div>
                  <span className="text-blue-900/60 font-mono text-[11px] font-bold">Investigation Log:</span>
                  <div className="p-3.5 rounded-xl bg-blue-50/50 border border-blue-100 text-blue-950 whitespace-pre-wrap mt-1 font-mono text-[11px]">
                    {selectedAlert.notes || 'No analyst notes yet recorded.'}
                  </div>
                </div>
              </div>

              {/* Triage Actions */}
              <div className="space-y-2 pt-2 border-t border-blue-100">
                <span className="text-[11px] font-extrabold uppercase tracking-wider text-blue-900/60 block">
                  Triage Status Transition
                </span>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'Investigating')}
                    className="py-2 px-2.5 rounded-xl bg-amber-50 hover:bg-amber-100 border border-amber-200 text-amber-800 text-xs font-bold transition-colors cursor-pointer"
                  >
                    Investigating
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'Blocked')}
                    className="py-2 px-2.5 rounded-xl bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-800 text-xs font-bold transition-colors cursor-pointer"
                  >
                    Block in Firewall
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'False_Positive')}
                    className="py-2 px-2.5 rounded-xl bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-bold transition-colors cursor-pointer"
                  >
                    False Positive
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'Resolved')}
                    className="py-2 px-2.5 rounded-xl bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 text-emerald-800 text-xs font-bold transition-colors cursor-pointer"
                  >
                    Mark Resolved
                  </button>
                </div>
              </div>

              {/* Add Note Input */}
              <div className="space-y-2 pt-2">
                <textarea
                  value={noteInput}
                  onChange={(e) => setNoteInput(e.target.value)}
                  placeholder="Add analyst triage notes..."
                  rows={2}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs focus:outline-none focus:border-blue-600"
                />
                <button
                  onClick={handleAddNote}
                  disabled={!noteInput.trim()}
                  className="w-full py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-colors disabled:opacity-40 shadow-xs cursor-pointer"
                >
                  Append Note to Record
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-blue-900/50 space-y-2">
              <MessageSquare className="h-8 w-8 text-blue-300 mx-auto" />
              <p className="text-xs font-medium">Select any incident from the list to view telemetry and triage status.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
