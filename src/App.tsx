import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { UrlScanner } from './components/UrlScanner';
import { SecureScoreResult } from './components/SecureScoreResult';
import { ScanResult, UserProfile } from './types';
import { auth, saveScanToFirestore } from './lib/firebase';
import { createLocalScanResult } from './lib/svm-engine';
import { onAuthStateChanged } from 'firebase/auth';

export default function App() {
  const [currentScanResult, setCurrentScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('securescore-theme');
      if (saved === 'dark' || saved === 'light') return saved;
      return 'dark'; // Default to Cyber Dark mode
    }
    return 'dark';
  });

  // Apply theme class to <html> element
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('securescore-theme', theme);
  }, [theme]);

  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Optional Firebase auth state listener
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
      if (firebaseUser) {
        setUser({
          uid: firebaseUser.uid,
          email: firebaseUser.email || '',
          displayName: firebaseUser.displayName || 'User',
          photoURL: firebaseUser.photoURL || undefined,
          role: 'Analyst',
          createdAt: Date.now(),
        });
      } else {
        setUser(null);
      }
    });

    return () => unsubscribe();
  }, []);

  // Execute Core URL Analysis Flow
  const handlePerformScan = async (url: string) => {
    setIsScanning(true);
    setCurrentUrl(url);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, userId: user?.uid }),
      });

      let scanResult: ScanResult;

      if (!response.ok) {
        // Use client-side SVM analysis fallback
        console.warn('Backend returned non-ok status, utilizing client-side SVM engine');
        scanResult = createLocalScanResult(url);
      } else {
        scanResult = await response.json();
      }

      setCurrentScanResult(scanResult);

      // Save scan to Firestore in the background
      saveScanToFirestore(scanResult, user?.uid).catch((err) =>
        console.warn('Firestore save notice:', err)
      );
    } catch (err) {
      console.warn('Fetch error during scan, using client-side SVM engine:', err);
      const fallbackResult = createLocalScanResult(url);
      setCurrentScanResult(fallbackResult);
      saveScanToFirestore(fallbackResult, user?.uid).catch((saveErr) =>
        console.warn('Firestore fallback save notice:', saveErr)
      );
    } finally {
      setIsScanning(false);
    }
  };

  const handleResetScan = () => {
    setCurrentScanResult(null);
    setCurrentUrl('');
  };

  return (
    <div className="relative min-h-screen bg-slate-50 dark:bg-[#060b13] cyber-grid-bg text-slate-900 dark:text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white transition-colors duration-200">
      {/* Subtle Ambient Cyber Scanlines Grid */}
      <div className="fixed inset-0 cyber-scanlines opacity-25 pointer-events-none z-30" />

      {/* Top Cyber Command Header */}
      <Navbar
        onResetScan={handleResetScan}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        hasActiveResult={Boolean(currentScanResult)}
      />

      {/* Main Single-View Content Area */}
      <main className="relative z-10 flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 py-8 sm:py-12 space-y-8">
        {/* Cyber Target Input Bar */}
        <UrlScanner
          onScan={handlePerformScan}
          isScanning={isScanning}
          initialUrl={currentUrl}
        />

        {/* Secure Score Results Section */}
        {currentScanResult && (
          <div id="secure-score-section" className="pt-2">
            <SecureScoreResult
              result={currentScanResult}
              onNewScan={handleResetScan}
            />
          </div>
        )}
      </main>

      {/* High-Tech Cyber HUD Footer */}
      <footer className="relative z-10 border-t border-slate-200 dark:border-cyan-500/20 bg-white/70 dark:bg-[#060b13]/80 backdrop-blur-md py-6 text-center text-xs text-slate-500 dark:text-slate-400">
        <div className="max-w-5xl mx-auto px-4 space-y-2">
          <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 font-cyber text-[11px] tracking-wider">
            <span className="font-black text-slate-900 dark:text-white">
              SECURESCORE CYBER-DEFENSE
            </span>
            <span className="text-slate-300 dark:text-slate-700">•</span>
            <span className="text-cyan-600 dark:text-cyan-400 font-bold">
              SVM-RBF DUAL KERNEL
            </span>
            <span className="text-slate-300 dark:text-slate-700">•</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-bold">
              LIVE DNS & NXDOMAIN SENSORS
            </span>
            <span className="text-slate-300 dark:text-slate-700">•</span>
            <span className="text-slate-500 dark:text-slate-400 font-mono">
              24 HEURISTIC VECTORS
            </span>
          </div>
          <p className="text-[11px] text-slate-400 dark:text-slate-500 font-tech">
            Continuous URL safety verification, brand spoof detection, cryptographic TLS assessment, and domain dormancy analysis.
          </p>
        </div>
      </footer>
    </div>
  );
}
