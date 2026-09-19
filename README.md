# URL Security Score Checker 🛡️

> Instant website link security scanner that evaluates any URL and provides a definitive Secure Score with clear safety insights.

🌐 **Live Website:** [https://bit.ly/4hdn6zF](https://bit.ly/4hdn6zF)

---

## 🚀 Overview

**URL Security Score Checker** provides real-time threat intelligence and vulnerability analysis for URLs. It combines heuristic inspection (lexical features, Shannon entropy, domain age/structure, suspicious keywords) with machine-learning threat classification and AI-driven deep analysis to deliver an actionable Secure Score (0–100) along with detailed safety recommendations.

---

## ⚡ Key Features

- **Instant URL Security Scoring**: Compute safety metrics (0–100 score) with clear classifications (*Safe*, *Caution*, *Phishing / Suspicious*).
- **Multi-Vector Analysis**:
  - Domain structure & SSL/HTTPS verification
  - High-risk TLD & IP address detection
  - Shannon entropy & lexical obfuscation analysis
  - Homoglyph & brand typosquatting detection
  - Redirection & URL shortener tracing
- **Interactive Cyberpunk / Light Theme**: Seamless toggle between Cyber Dark mode and clean light theme.
- **Scan History**: Save and inspect past scans with detailed risk breakdowns and quick re-tests.
- **AI-Powered Threat Insights**: In-depth explanations of flagged vectors and practical safety guidance.

---

## 🛠️ Tech Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS, Lucide React, Motion
- **Backend / Server**: Express 4, Node.js, `tsx`
- **Machine Learning & AI**: In-browser SVM heuristics & Google Gemini API
- **Database & Authentication**: Firebase Firestore & Firebase Auth
- **Build Tool**: Vite 6, esbuild

---

## 📦 Getting Started

### 1. Clone or Export the Repository

```bash
git clone <your-github-repo-url>
cd url-security-score-checker
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Copy the example environment file and add your credentials:

```bash
cp .env.example .env
```

Ensure `GEMINI_API_KEY` (optional for enhanced AI insights) is set.

### 4. Run Development Server

```bash
npm run dev
```

The application will start at `http://localhost:3000`.

### 5. Production Build

```bash
npm run build
npm run start
```

---

## 🌐 Website & Live Demo

- **URL:** [https://bit.ly/4hdn6zF](https://bit.ly/4hdn6zF)

---

## 📄 License

This project is licensed under the MIT License.
