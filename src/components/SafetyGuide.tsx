import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lightbulb,
  ExternalLink,
  BookOpen,
  Award,
  Sparkles,
  ArrowRight,
  RotateCcw,
  Smartphone,
  Mail,
  Lock,
  Globe
} from 'lucide-react';

interface SafetyGuideProps {
  onScanUrl?: (url: string) => void;
  onClose?: () => void;
}

const QUIZ_QUESTIONS = [
  {
    id: 1,
    scenario: 'You receive an SMS text saying: "USPS: Your package is waiting at our depot. Pay $1.50 redelivery fee now at usps-track-parcel24.top/claim"',
    url: 'http://usps-track-parcel24.top/claim',
    question: 'Is this link safe or a phishing scam?',
    options: [
      { text: 'Scam / Phishing Lure (Never click)', correct: true, explanation: 'Correct! Official USPS uses "usps.com". The domain "usps-track-parcel24.top" is a fake lookalike registered to steal your credit card!' },
      { text: 'Safe (It mentions USPS and has a tracking code)', correct: false, explanation: 'Incorrect! Anyone can put "USPS" in a fake domain name or text message. Always check the real domain (usps.com).' },
    ],
  },
  {
    id: 2,
    scenario: 'You are logging into your university or company portal. The address bar shows: "https://login.microsoftonline.com/common/oauth2"',
    url: 'https://login.microsoftonline.com/common/oauth2',
    question: 'Is this link safe or a phishing scam?',
    options: [
      { text: 'Safe (Official Microsoft login domain with valid SSL)', correct: true, explanation: 'Correct! "microsoftonline.com" is Microsoft\'s official corporate authentication domain.' },
      { text: 'Scam (It has too many letters in the URL)', correct: false, explanation: 'Incorrect! Complex URLs with standard paths on verified domains like microsoftonline.com are legitimate.' },
    ],
  },
  {
    id: 3,
    scenario: 'You get an urgent email: "Your PayPal account is suspended! Verify identity immediately at http://paypa1-security-verification.xyz/login"',
    url: 'http://paypa1-security-verification.xyz/login',
    question: 'What are the red flags in this URL?',
    options: [
      { text: 'Typo "paypa1" (number 1 instead of L), .xyz extension, and insecure HTTP', correct: true, explanation: 'Spot on! Scammers use letter-swaps (typosquatting) like "paypa1" and cheap .xyz domains to trick you.' },
      { text: 'Nothing, it says "security-verification" so it is verified', correct: false, explanation: 'Incorrect! Scammers frequently add words like "security", "verify", and "login" to make scams look authentic.' },
    ],
  },
  {
    id: 4,
    scenario: 'A friend sends you a link: "Look who died in an accident: https://facebook-video-view.click/id=99281"',
    url: 'https://facebook-video-view.click/id=99281',
    question: 'How should you react?',
    options: [
      { text: 'Do NOT click — It is a social media credential harvester or malware lure', correct: true, explanation: 'Exactly! This is a classic "Shock Lure" scam designed to panic you into typing your Facebook password.' },
      { text: 'Click quickly to see who it is', correct: false, explanation: 'Never! Emotional shock messages are the #1 way scammers bypass your natural caution.' },
    ],
  },
];

export const SafetyGuide: React.FC<SafetyGuideProps> = ({ onScanUrl, onClose }) => {
  const [activeSection, setActiveSection] = useState<'rules' | 'anatomy' | 'quiz' | 'emergency'>('rules');
  const [currentQuizIndex, setCurrentQuizIndex] = useState(0);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [quizScore, setQuizScore] = useState(0);
  const [quizCompleted, setQuizCompleted] = useState(false);

  const handleAnswer = (index: number) => {
    if (selectedOption !== null) return;
    setSelectedOption(index);
    if (QUIZ_QUESTIONS[currentQuizIndex].options[index].correct) {
      setQuizScore((prev) => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuizIndex < QUIZ_QUESTIONS.length - 1) {
      setCurrentQuizIndex((prev) => prev + 1);
      setSelectedOption(null);
    } else {
      setQuizCompleted(true);
    }
  };

  const handleRestartQuiz = () => {
    setCurrentQuizIndex(0);
    setSelectedOption(null);
    setQuizScore(0);
    setQuizCompleted(false);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 shadow-xl shadow-blue-900/5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-bold">
              <Lightbulb className="h-3.5 w-3.5 text-blue-600" />
              <span>Easy Everyday Security Guide</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-blue-950 tracking-tight">
              How to Spot Fake Links & Stay Safe
            </h1>
            <p className="text-sm text-blue-900/70 max-w-xl leading-relaxed">
              Phishing scams trick people into giving away passwords, credit cards, or personal data. Here is everything you need to know in simple, plain English.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {onClose && (
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-2xl bg-blue-50 hover:bg-blue-100 text-blue-900 text-xs font-bold transition-colors cursor-pointer border border-blue-200"
              >
                Back to Scanner
              </button>
            )}
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap items-center gap-2 mt-6 pt-6 border-t border-blue-100">
          <button
            onClick={() => setActiveSection('rules')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
              activeSection === 'rules'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                : 'bg-blue-50 text-blue-900 hover:bg-blue-100'
            }`}
          >
            <ShieldCheck className="h-4 w-4" />
            <span>4 Golden Rules</span>
          </button>

          <button
            onClick={() => setActiveSection('anatomy')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
              activeSection === 'anatomy'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                : 'bg-blue-50 text-blue-900 hover:bg-blue-100'
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>How to Read a Link</span>
          </button>

          <button
            onClick={() => setActiveSection('quiz')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
              activeSection === 'quiz'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                : 'bg-blue-50 text-blue-900 hover:bg-blue-100'
            }`}
          >
            <Award className="h-4 w-4" />
            <span>Practice Quiz (Test Yourself)</span>
          </button>

          <button
            onClick={() => setActiveSection('emergency')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
              activeSection === 'emergency'
                ? 'bg-rose-600 text-white shadow-md shadow-rose-600/20'
                : 'bg-blue-50 text-blue-900 hover:bg-blue-100'
            }`}
          >
            <AlertTriangle className="h-4 w-4" />
            <span>What If I Already Clicked?</span>
          </button>
        </div>
      </div>

      {/* SECTION 1: 4 Golden Rules */}
      {activeSection === 'rules' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-3 shadow-xl shadow-blue-900/5">
            <div className="h-10 w-10 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700 font-extrabold text-sm">
              1
            </div>
            <h2 className="text-base font-extrabold text-blue-950">Look at the Real Domain (Before the "/")</h2>
            <p className="text-xs text-blue-900/75 leading-relaxed">
              Scammers try to confuse you by putting names in the front. For example,{' '}
              <span className="font-mono text-rose-700 bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded font-bold">paypal.com.verify-login.xyz</span> is NOT PayPal. It is actually a website called <strong className="text-blue-950">verify-login.xyz</strong>!
            </p>
          </div>

          <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-3 shadow-xl shadow-blue-900/5">
            <div className="h-10 w-10 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700 font-extrabold text-sm">
              2
            </div>
            <h2 className="text-base font-extrabold text-blue-950">Beware of Urgent Threats & Free Prizes</h2>
            <p className="text-xs text-blue-900/75 leading-relaxed">
              Scammers create fake urgency like <em>"Your bank account will be closed in 24 hours"</em> or <em>"You won a $500 gift card"</em>. Real companies never ask you to verify passwords via emergency SMS.
            </p>
          </div>

          <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-3 shadow-xl shadow-blue-900/5">
            <div className="h-10 w-10 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700 font-extrabold text-sm">
              3
            </div>
            <h2 className="text-base font-extrabold text-blue-950">Inspect Strange Website Extensions (.xyz, .top, .click)</h2>
            <p className="text-xs text-blue-900/75 leading-relaxed">
              Most legitimate businesses and services use familiar endings like <span className="text-emerald-700 font-bold">.com</span>, <span className="text-emerald-700 font-bold">.org</span>, or <span className="text-emerald-700 font-bold">.gov</span>. Cheap disposable endings like <span className="text-amber-700 font-bold">.xyz</span>, <span className="text-amber-700 font-bold">.top</span>, or <span className="text-amber-700 font-bold">.click</span> are frequently used for fast scams.
            </p>
          </div>

          <div className="p-6 rounded-3xl bg-white border border-blue-100 space-y-3 shadow-xl shadow-blue-900/5">
            <div className="h-10 w-10 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700 font-extrabold text-sm">
              4
            </div>
            <h2 className="text-base font-extrabold text-blue-950">When in Doubt, Type the Website Yourself</h2>
            <p className="text-xs text-blue-900/75 leading-relaxed">
              If an email or text says your Netflix, Amazon, or Bank account has a problem, do NOT click their link. Open a browser and manually type <span className="text-blue-700 font-mono font-bold">netflix.com</span> or <span className="text-blue-700 font-mono font-bold">amazon.com</span> directly.
            </p>
          </div>
        </div>
      )}

      {/* SECTION 2: Anatomy of a Link */}
      {activeSection === 'anatomy' && (
        <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
          <div>
            <h2 className="text-lg font-extrabold text-blue-950">How to Read Any Website Link (URL)</h2>
            <p className="text-xs text-blue-900/70 mt-1">
              Every web link is made of 4 main parts. Understanding them makes spotting fake links easy:
            </p>
          </div>

          {/* Visual Link Breakdown */}
          <div className="p-5 rounded-2xl bg-slate-50 border border-blue-200 overflow-x-auto">
            <div className="flex items-center gap-1.5 font-mono text-xs sm:text-sm whitespace-nowrap">
              <span className="p-2.5 rounded-xl bg-blue-100 text-blue-900 border border-blue-300 font-bold">
                https://
                <span className="block text-[10px] text-blue-700 font-sans mt-0.5">Protocol</span>
              </span>
              <span className="p-2.5 rounded-xl bg-amber-100 text-amber-900 border border-amber-300 font-bold">
                accounts.login.
                <span className="block text-[10px] text-amber-800 font-sans mt-0.5">Subdomain (Anyone can make this)</span>
              </span>
              <span className="p-2.5 rounded-xl bg-rose-100 text-rose-900 border border-rose-300 font-extrabold">
                chase-verify.xyz
                <span className="block text-[10px] text-rose-800 font-sans mt-0.5">Real Domain Name (The True Owner)</span>
              </span>
              <span className="p-2.5 rounded-xl bg-slate-200 text-slate-900 border border-slate-300 font-medium">
                /signin/password.php
                <span className="block text-[10px] text-slate-700 font-sans mt-0.5">Page Path</span>
              </span>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-extrabold text-blue-950">Key Takeaways:</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs text-blue-950">
              <div className="p-4 rounded-2xl bg-emerald-50/70 border border-emerald-200 flex items-start gap-2.5">
                <span className="text-emerald-700 font-black text-sm">✓</span>
                <div>
                  <p className="font-extrabold text-blue-950">The Real Owner is the part right before the first single "/"</p>
                  <p className="text-blue-900/70 text-[11px] mt-0.5">In "google.com/search", google.com is the true domain owner.</p>
                </div>
              </div>
              <div className="p-4 rounded-2xl bg-rose-50/70 border border-rose-200 flex items-start gap-2.5">
                <span className="text-rose-700 font-black text-sm">✗</span>
                <div>
                  <p className="font-extrabold text-blue-950">Hyphens in domain names are a common fraud technique</p>
                  <p className="text-blue-900/70 text-[11px] mt-0.5">"paypal-security.com" is NOT owned by PayPal.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 3: Practice Quiz */}
      {activeSection === 'quiz' && (
        <div className="rounded-3xl bg-white border border-blue-100 p-6 sm:p-8 space-y-6 shadow-xl shadow-blue-900/5">
          {!quizCompleted ? (
            <div className="space-y-6">
              {/* Quiz Progress */}
              <div className="flex items-center justify-between text-xs text-blue-900/70 border-b border-blue-100 pb-4">
                <span className="font-extrabold text-blue-700">
                  Question {currentQuizIndex + 1} of {QUIZ_QUESTIONS.length}
                </span>
                <span className="font-mono font-bold text-blue-950">
                  Score: {quizScore} / {QUIZ_QUESTIONS.length}
                </span>
              </div>

              {/* Scenario Box */}
              <div className="p-5 rounded-2xl bg-blue-50/60 border border-blue-100 space-y-2">
                <span className="text-[11px] font-extrabold uppercase tracking-wider text-blue-700">
                  Real-World Scenario:
                </span>
                <p className="text-sm text-blue-950 font-semibold">
                  {QUIZ_QUESTIONS[currentQuizIndex].scenario}
                </p>
                <div className="p-3 rounded-xl bg-white border border-blue-200 font-mono text-xs font-bold text-amber-800 break-all select-all shadow-xs">
                  {QUIZ_QUESTIONS[currentQuizIndex].url}
                </div>
              </div>

              {/* Question */}
              <h3 className="text-base font-extrabold text-blue-950">
                {QUIZ_QUESTIONS[currentQuizIndex].question}
              </h3>

              {/* Option Choices */}
              <div className="space-y-3">
                {QUIZ_QUESTIONS[currentQuizIndex].options.map((opt, idx) => {
                  const isSelected = selectedOption === idx;
                  const showFeedback = selectedOption !== null;
                  return (
                    <button
                      key={idx}
                      onClick={() => handleAnswer(idx)}
                      disabled={selectedOption !== null}
                      className={`w-full text-left p-4 rounded-2xl border text-xs sm:text-sm font-semibold transition-all flex items-center justify-between gap-3 cursor-pointer ${
                        !showFeedback
                          ? 'bg-white hover:bg-blue-50/70 border-blue-200 text-blue-950 shadow-xs'
                          : opt.correct
                          ? 'bg-emerald-50 border-emerald-300 text-emerald-950'
                          : isSelected
                          ? 'bg-rose-50 border-rose-300 text-rose-950'
                          : 'bg-slate-50 border-slate-200 text-slate-400 opacity-60'
                      }`}
                    >
                      <span>{opt.text}</span>
                      {showFeedback && opt.correct && (
                        <CheckCircle2 className="h-5 w-5 text-emerald-600 shrink-0" />
                      )}
                      {showFeedback && isSelected && !opt.correct && (
                        <XCircle className="h-5 w-5 text-rose-600 shrink-0" />
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Feedback Explainer */}
              {selectedOption !== null && (
                <div className="p-5 rounded-2xl bg-blue-50 border border-blue-200 text-xs text-blue-950 space-y-3 animate-in fade-in">
                  <p className="font-semibold">
                    {QUIZ_QUESTIONS[currentQuizIndex].options[selectedOption].explanation}
                  </p>
                  <div className="flex items-center justify-between pt-2 border-t border-blue-200">
                    {onScanUrl && (
                      <button
                        onClick={() => onScanUrl(QUIZ_QUESTIONS[currentQuizIndex].url)}
                        className="text-blue-700 hover:text-blue-900 font-extrabold inline-flex items-center gap-1 cursor-pointer"
                      >
                        <span>Scan this exact URL in PhishGuard</span>
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    )}
                    <button
                      onClick={handleNextQuestion}
                      className="ml-auto px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-extrabold text-xs shadow-md shadow-blue-600/20 transition-all cursor-pointer"
                    >
                      {currentQuizIndex < QUIZ_QUESTIONS.length - 1 ? 'Next Question' : 'See Results'}
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-8 space-y-4">
              <div className="h-16 w-16 mx-auto rounded-3xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-sm">
                <Award className="h-8 w-8" />
              </div>
              <h2 className="text-2xl font-extrabold text-blue-950">Quiz Completed!</h2>
              <p className="text-blue-900 text-sm font-semibold">
                You scored <span className="font-extrabold text-blue-700">{quizScore} out of {QUIZ_QUESTIONS.length}</span>!
              </p>
              <p className="text-xs text-blue-900/70 max-w-md mx-auto leading-relaxed">
                {quizScore === QUIZ_QUESTIONS.length
                  ? 'Outstanding! You have expert scam-spotting skills. You are well-protected against malicious phishing scams.'
                  : 'Great practice! Keeping an eye on domain names and avoiding urgency lures will keep you and your accounts safe.'}
              </p>
              <button
                onClick={handleRestartQuiz}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-2xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-all shadow-md shadow-blue-600/20 cursor-pointer"
              >
                <RotateCcw className="h-4 w-4" />
                <span>Try Quiz Again</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* SECTION 4: Emergency Response */}
      {activeSection === 'emergency' && (
        <div className="rounded-3xl bg-rose-50/50 border border-rose-200 p-6 sm:p-8 space-y-6 shadow-xl shadow-rose-900/5">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-rose-700 font-extrabold text-sm">
              <AlertTriangle className="h-5 w-5" />
              <span>Emergency Steps if You Entered Your Password on a Suspicious Link</span>
            </div>
            <p className="text-xs text-blue-950">
              Do not panic. Taking these fast actions immediately locks attackers out:
            </p>
          </div>

          <div className="space-y-3.5">
            <div className="p-5 rounded-2xl bg-white border border-rose-200 flex items-start gap-3.5 shadow-xs">
              <div className="h-7 w-7 rounded-xl bg-rose-100 text-rose-800 font-extrabold text-xs flex items-center justify-center shrink-0 mt-0.5">
                1
              </div>
              <div>
                <h3 className="text-xs sm:text-sm font-extrabold text-blue-950">Change your password immediately on the REAL official site</h3>
                <p className="text-xs text-blue-900/75 mt-1 leading-relaxed">
                  Go directly to the official website (e.g. google.com, paypal.com, or your bank's app) and reset your password right now.
                </p>
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-white border border-rose-200 flex items-start gap-3.5 shadow-xs">
              <div className="h-7 w-7 rounded-xl bg-rose-100 text-rose-800 font-extrabold text-xs flex items-center justify-center shrink-0 mt-0.5">
                2
              </div>
              <div>
                <h3 className="text-xs sm:text-sm font-extrabold text-blue-950">Turn on Two-Factor Authentication (2FA)</h3>
                <p className="text-xs text-blue-900/75 mt-1 leading-relaxed">
                  Enable 2FA (SMS code or Authenticator App). Even if a scammer has your password, they cannot log in without the second code.
                </p>
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-white border border-rose-200 flex items-start gap-3.5 shadow-xs">
              <div className="h-7 w-7 rounded-xl bg-rose-100 text-rose-800 font-extrabold text-xs flex items-center justify-center shrink-0 mt-0.5">
                3
              </div>
              <div>
                <h3 className="text-xs sm:text-sm font-extrabold text-blue-950">Freeze your card if you entered payment details</h3>
                <p className="text-xs text-blue-900/75 mt-1 leading-relaxed">
                  If you typed in your credit card or bank details, open your banking app and temporarily lock/freeze the card, then call your bank.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
