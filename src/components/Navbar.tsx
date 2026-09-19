import React, { useState } from 'react';
import {
  ShieldCheck,
  Sun,
  Moon,
  RotateCcw,
  Volume2,
  VolumeX,
  Terminal,
  Activity,
  Radio,
} from 'lucide-react';
import { cyberAudio } from '../lib/cyber-sound';

interface NavbarProps {
  onResetScan?: () => void;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  hasActiveResult?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  onResetScan,
  theme,
  onToggleTheme,
  hasActiveResult,
}) => {
  const [audioEnabled, setAudioEnabled] = useState(() => cyberAudio.enabled);

  const handleToggleAudio = () => {
    const nextState = cyberAudio.toggleAudio();
    setAudioEnabled(nextState);
  };

  const handleLogoClick = () => {
    cyberAudio.playBlip(1200);
    if (onResetScan) onResetScan();
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/80 dark:border-cyan-500/20 bg-white/95 dark:bg-[#060b13]/95 backdrop-blur-md shadow-sm transition-colors">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Cyber Status Header */}
          <div className="flex items-center gap-3 sm:gap-4">
            <button
              id="brand-logo-btn"
              onClick={handleLogoClick}
              className="flex items-center gap-3 text-left group focus:outline-none cursor-pointer"
            >
              {/* Tactical Cyber Shield Icon with Hex Glow */}
              <div className="relative h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 p-0.5 shadow-md shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all">
                <div className="h-full w-full bg-[#070e1e] rounded-[10px] flex items-center justify-center border border-cyan-400/40 group-hover:border-cyan-400 transition-colors">
                  <ShieldCheck className="h-5 w-5 text-cyan-400 group-hover:scale-110 transition-transform" />
                </div>
                <div className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping opacity-75" />
                <div className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-emerald-500" />
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <span className="font-cyber font-black text-base sm:text-lg tracking-wider text-slate-900 dark:text-white flex items-center gap-1.5">
                    SECURE<span className="text-cyan-600 dark:text-cyan-400 neon-glow-cyan">SCORE</span>
                  </span>
                  <span className="text-[10px] font-cyber tracking-widest uppercase px-1.5 py-0.5 rounded bg-cyan-50 dark:bg-cyan-950/80 text-cyan-700 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-500/50 font-bold">
                    CYBER·HUD
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400 font-tech">
                  <span className="hidden sm:inline font-mono text-[10px] text-cyan-600 dark:text-cyan-400 font-semibold">
                    SYS.GRID // v4.2-DEFCON
                  </span>
                  <span className="hidden sm:inline text-slate-300 dark:text-slate-700">•</span>
                  <span className="font-medium tracking-wide truncate max-w-[200px] sm:max-w-none">
                    URL Threat & Phishing Detection Radar
                  </span>
                </div>
              </div>
            </button>
          </div>

          {/* Right Controls: Telemetry Beacon, Audio Toggle, Theme, Reset */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Live Cyber Beacon Status (Desktop) */}
            <div className="hidden md:flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-cyan-500/20 text-[11px] font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
              <span className="text-slate-600 dark:text-slate-300 font-semibold">DEFENSE GRID</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-bold">ARMED</span>
            </div>

            {/* Tactical Audio Feedback Toggle */}
            <button
              id="cyber-audio-toggle-btn"
              onClick={handleToggleAudio}
              className={`flex items-center gap-1.5 px-2.5 py-2 rounded-xl border text-xs font-mono font-bold transition-all cursor-pointer ${
                audioEnabled
                  ? 'bg-cyan-50 dark:bg-cyan-950/40 border-cyan-200 dark:border-cyan-500/40 text-cyan-700 dark:text-cyan-300'
                  : 'bg-slate-100 dark:bg-slate-850 border-slate-200 dark:border-slate-800 text-slate-400'
              }`}
              title={audioEnabled ? 'Cyber Audio: ON (Click to Mute)' : 'Cyber Audio: MUTED (Click to Enable)'}
              aria-label={audioEnabled ? 'Mute Cyber Audio' : 'Enable Cyber Audio'}
            >
              {audioEnabled ? (
                <>
                  <Volume2 className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                  <span className="hidden sm:inline text-[11px]">AUDIO</span>
                </>
              ) : (
                <>
                  <VolumeX className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline text-[11px]">MUTED</span>
                </>
              )}
            </button>

            {/* New Scan Reset Button */}
            {hasActiveResult && onResetScan && (
              <button
                id="header-new-scan-btn"
                onClick={() => {
                  cyberAudio.playBlip(1000);
                  onResetScan();
                }}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-cyan-50 dark:bg-cyan-950/50 hover:bg-cyan-100 dark:hover:bg-cyan-900/60 border border-cyan-200 dark:border-cyan-500/40 text-xs font-mono font-bold text-cyan-700 dark:text-cyan-300 transition-all cursor-pointer shadow-xs"
              >
                <RotateCcw className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                <span className="hidden sm:inline">NEW TARGET</span>
                <span className="sm:hidden">RESET</span>
              </button>
            )}

            {/* Dark/Light Theme Toggle */}
            <button
              id="theme-toggle-btn"
              onClick={() => {
                cyberAudio.playBlip(800);
                onToggleTheme();
              }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-xs font-bold text-slate-800 dark:text-slate-200 transition-all cursor-pointer shadow-xs"
              title={theme === 'dark' ? 'Switch to Cyber Light Mode' : 'Switch to Cyber Dark Mode'}
              aria-label="Toggle Theme"
            >
              {theme === 'dark' ? (
                <>
                  <Sun className="h-4 w-4 text-amber-400" />
                  <span className="hidden sm:inline font-mono text-[11px]">LIGHT</span>
                </>
              ) : (
                <>
                  <Moon className="h-4 w-4 text-cyan-600" />
                  <span className="hidden sm:inline font-mono text-[11px]">DARK</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
