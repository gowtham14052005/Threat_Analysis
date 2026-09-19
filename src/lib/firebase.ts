import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  signInAnonymously,
  updateProfile,
  User
} from 'firebase/auth';
import {
  getFirestore,
  collection,
  doc,
  setDoc,
  getDoc,
  getDocs,
  addDoc,
  onSnapshot,
  query,
  where,
  orderBy,
  updateDoc,
  deleteDoc,
  limit,
  Firestore
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';
import { ScanResult, SecurityAlert, WatchlistItem, UserProfile } from '../types';

// Initialize Firebase App
const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();

export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

// Initialize Firestore with specific databaseId from config
export const db: Firestore = getFirestore(app, firebaseConfig.firestoreDatabaseId || '(default)');

// Helper: Save scan result to Firestore
export async function saveScanToFirestore(scan: ScanResult, userId?: string): Promise<string> {
  try {
    const scanData = {
      ...scan,
      userId: userId || auth.currentUser?.uid || 'anonymous',
      createdAt: Date.now(),
    };
    const colRef = collection(db, 'scans');
    const docRef = await addDoc(colRef, scanData);
    return docRef.id;
  } catch (err) {
    console.warn('Firestore saveScan error (falling back to local cache):', err);
    // Return scan id as fallback
    return scan.id;
  }
}

// Helper: Create security alert in Firestore
export async function createAlertInFirestore(alert: Omit<SecurityAlert, 'id' | 'createdAt'>): Promise<string> {
  try {
    const alertData = {
      ...alert,
      userId: alert.userId || auth.currentUser?.uid || 'anonymous',
      createdAt: Date.now(),
    };
    const colRef = collection(db, 'alerts');
    const docRef = await addDoc(colRef, alertData);
    return docRef.id;
  } catch (err) {
    console.warn('Firestore createAlert error:', err);
    return 'local-' + Date.now();
  }
}

// Helper: Update alert status in Firestore
export async function updateAlertStatusInFirestore(
  alertId: string,
  status: SecurityAlert['status'],
  notes?: string
): Promise<void> {
  try {
    const docRef = doc(db, 'alerts', alertId);
    await updateDoc(docRef, {
      status,
      ...(notes ? { notes } : {}),
      ...(status === 'Resolved' ? { resolvedAt: Date.now() } : {})
    });
  } catch (err) {
    console.warn('Firestore updateAlert error:', err);
  }
}

// Helper: Add item to Watchlist
export async function addToWatchlist(item: Omit<WatchlistItem, 'id' | 'addedAt'>): Promise<string> {
  try {
    const data = {
      ...item,
      userId: item.userId || auth.currentUser?.uid || 'anonymous',
      addedAt: Date.now(),
    };
    const docRef = await addDoc(collection(db, 'watchlist'), data);
    return docRef.id;
  } catch (err) {
    console.warn('Firestore addToWatchlist error:', err);
    return 'watch-' + Date.now();
  }
}

// Helper: Remove item from Watchlist
export async function removeFromWatchlist(id: string): Promise<void> {
  try {
    await deleteDoc(doc(db, 'watchlist', id));
  } catch (err) {
    console.warn('Firestore removeFromWatchlist error:', err);
  }
}

// Helper: Convert Firebase User to UserProfile
export function mapUserToProfile(user: User): UserProfile {
  return {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName || user.email?.split('@')[0] || 'Security Analyst',
    photoURL: user.photoURL || undefined,
    role: 'Security Analyst',
    createdAt: Date.now(),
  };
}

// Auth wrappers
export async function signInWithGooglePopup(): Promise<UserProfile> {
  const cred = await signInWithPopup(auth, googleProvider);
  return mapUserToProfile(cred.user);
}

export async function signInWithEmailPassword(email: string, pass: string): Promise<UserProfile> {
  const cred = await signInWithEmailAndPassword(auth, email, pass);
  return mapUserToProfile(cred.user);
}

export async function signUpWithEmailPassword(email: string, pass: string, displayName?: string): Promise<UserProfile> {
  const cred = await createUserWithEmailAndPassword(auth, email, pass);
  if (displayName) {
    await updateProfile(cred.user, { displayName });
  }
  return mapUserToProfile(cred.user);
}

export async function signInAnonymouslyWithFirebase(): Promise<UserProfile> {
  const cred = await signInAnonymously(auth);
  return mapUserToProfile(cred.user);
}

// Auth helpers
export {
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  signInAnonymously,
  updateProfile,
  collection,
  doc,
  setDoc,
  getDoc,
  getDocs,
  addDoc,
  onSnapshot,
  query,
  where,
  orderBy,
  updateDoc,
  deleteDoc,
  limit
};
export type { User };
