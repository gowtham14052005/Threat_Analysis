import React, { useState } from 'react';
import {
  ShieldCheck,
  X,
  Mail,
  Lock,
  User,
  ArrowRight,
  Sparkles,
  AlertCircle,
  UserCheck
} from 'lucide-react';
import {
  signInWithGooglePopup,
  signInWithEmailPassword,
  signUpWithEmailPassword,
  signInAnonymouslyWithFirebase
} from '../lib/firebase';
import { UserProfile } from '../types';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (user: UserProfile) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isSignUp) {
        const user = await signUpWithEmailPassword(email, password, displayName || undefined);
        onSuccess(user);
      } else {
        const user = await signInWithEmailPassword(email, password);
        onSuccess(user);
      }
      onClose();
    } catch (err: any) {
      console.error('Auth error:', err);
      if (err.code === 'auth/invalid-credential' || err.code === 'auth/wrong-password') {
        setError('Invalid email or password.');
      } else if (err.code === 'auth/email-already-in-use') {
        setError('An account already exists with this email.');
      } else if (err.code === 'auth/weak-password') {
        setError('Password should be at least 6 characters.');
      } else {
        setError(err.message || 'Authentication failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    setLoading(true);
    try {
      const user = await signInWithGooglePopup();
      onSuccess(user);
      onClose();
    } catch (err: any) {
      console.error('Google Sign-in error:', err);
      setError(err.message || 'Google sign-in was cancelled.');
    } finally {
      setLoading(false);
    }
  };

  const handleGuestSignIn = async () => {
    setError(null);
    setLoading(true);
    try {
      const user = await signInAnonymouslyWithFirebase();
      onSuccess(user);
      onClose();
    } catch (err: any) {
      console.error('Guest sign-in error:', err);
      setError(err.message || 'Anonymous guest session failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-blue-950/40 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-md p-6 sm:p-8 rounded-3xl bg-white border border-blue-200 shadow-2xl space-y-6">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-full text-blue-900/60 hover:text-blue-950 hover:bg-blue-50 transition-colors cursor-pointer"
        >
          <X className="h-4 w-4" />
        </button>

        {/* Header */}
        <div className="text-center space-y-2">
          <div className="h-12 w-12 rounded-2xl bg-blue-50 border border-blue-200 text-blue-600 flex items-center justify-center mx-auto shadow-sm">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h2 className="text-2xl font-extrabold text-blue-950">
            {isSignUp ? 'Create Security Account' : 'Analyst Sign In'}
          </h2>
          <p className="text-xs text-blue-900/70">
            {isSignUp
              ? 'Enable cloud scan history synchronization and real-time alerts.'
              : 'Sign in to access your saved threat audits and watchlist.'}
          </p>
        </div>

        {/* Google OAuth & Guest Quick Sign-In */}
        <div className="space-y-2.5">
          <button
            onClick={handleGoogleSignIn}
            disabled={loading}
            className="w-full flex items-center justify-center gap-3 py-2.5 px-4 rounded-2xl bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-bold transition-all shadow-xs cursor-pointer"
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Continue with Google</span>
          </button>

          <button
            onClick={handleGuestSignIn}
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-2xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-900 text-xs font-bold transition-all cursor-pointer shadow-xs"
          >
            <UserCheck className="h-3.5 w-3.5 text-blue-600" />
            <span>Continue as Guest (Instant Access)</span>
          </button>
        </div>

        <div className="flex items-center gap-3">
          <div className="h-px bg-blue-100 flex-1" />
          <span className="text-[11px] font-mono text-blue-900/50 uppercase font-bold">Or with Email</span>
          <div className="h-px bg-blue-100 flex-1" />
        </div>

        {/* Email & Password Form */}
        <form onSubmit={handleEmailAuth} className="space-y-3.5">
          {isSignUp && (
            <div className="space-y-1">
              <label className="text-[11px] font-bold text-blue-950">Display Name</label>
              <div className="relative">
                <User className="absolute left-3.5 top-2.5 h-4 w-4 text-blue-400" />
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Alex Security"
                  className="w-full pl-10 pr-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600"
                />
              </div>
            </div>
          )}

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-blue-950">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-2.5 h-4 w-4 text-blue-400" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@domain.com"
                className="w-full pl-10 pr-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-blue-950">Password</label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-2.5 h-4 w-4 text-blue-400" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-10 pr-3.5 py-2 rounded-xl bg-slate-50 border border-blue-200 text-blue-950 text-xs placeholder-blue-900/40 focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center gap-2 font-medium">
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-600" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-md shadow-blue-600/20 transition-all disabled:opacity-50 cursor-pointer"
          >
            {loading ? (
              <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
            ) : (
              <>
                <span>{isSignUp ? 'Create Security Account' : 'Sign In'}</span>
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </form>

        {/* Toggle between Sign In & Sign Up */}
        <div className="text-center pt-2 border-t border-blue-100">
          <button
            onClick={() => {
              setIsSignUp(!isSignUp);
              setError(null);
            }}
            className="text-xs text-blue-600 hover:text-blue-800 font-bold transition-colors cursor-pointer"
          >
            {isSignUp ? 'Already have an account? Sign In' : "Don't have an account? Create one"}
          </button>
        </div>
      </div>
    </div>
  );
};
