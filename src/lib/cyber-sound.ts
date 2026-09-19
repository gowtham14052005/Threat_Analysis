/**
 * Cyber Audio Synthesizer
 * Generates lightweight, tactile, futuristic UI audio feedback using the standard Web Audio API.
 * 0 external audio dependencies or network requests.
 */

class CyberAudioSynthesizer {
  private ctx: AudioContext | null = null;
  public enabled: boolean = true;

  constructor() {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('securescore-cyber-audio');
      this.enabled = saved !== 'false';
    }
  }

  public toggleAudio(): boolean {
    this.enabled = !this.enabled;
    if (typeof window !== 'undefined') {
      localStorage.setItem('securescore-cyber-audio', String(this.enabled));
    }
    if (this.enabled) {
      this.playBlip(900);
    }
    return this.enabled;
  }

  private init(): boolean {
    if (!this.enabled || typeof window === 'undefined') return false;
    try {
      if (!this.ctx) {
        const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        if (AudioCtx) {
          this.ctx = new AudioCtx();
        }
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        this.ctx.resume().catch(() => {});
      }
      return !!this.ctx;
    } catch {
      return false;
    }
  }

  /**
   * Subtle high-frequency micro blip for cyber click / target acquisition
   */
  public playBlip(frequency = 1100): void {
    if (!this.init() || !this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const t = this.ctx.currentTime;
      osc.type = 'sine';
      osc.frequency.setValueAtTime(frequency, t);
      osc.frequency.exponentialRampToValueAtTime(frequency * 1.5, t + 0.035);

      gain.gain.setValueAtTime(0.03, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.035);

      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(t);
      osc.stop(t + 0.035);
    } catch {}
  }

  /**
   * Laser scan sweep pulse played during URL inspection
   */
  public playScanPulse(): void {
    if (!this.init() || !this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const t = this.ctx.currentTime;
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(320, t);
      osc.frequency.linearRampToValueAtTime(840, t + 0.12);

      gain.gain.setValueAtTime(0.025, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.12);

      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(t);
      osc.stop(t + 0.12);
    } catch {}
  }

  /**
   * Harmonic cyber chord for safe score verdict
   */
  public playSafeHarmonic(): void {
    if (!this.init() || !this.ctx) return;
    try {
      const frequencies = [523.25, 659.25, 783.99, 1046.5]; // C5, E5, G5, C6
      const baseTime = this.ctx.currentTime;
      frequencies.forEach((freq, idx) => {
        const osc = this.ctx!.createOscillator();
        const gain = this.ctx!.createGain();
        const t = baseTime + idx * 0.055;
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, t);

        gain.gain.setValueAtTime(0.03, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.28);

        osc.connect(gain);
        gain.connect(this.ctx!.destination);
        osc.start(t);
        osc.stop(t + 0.28);
      });
    } catch {}
  }

  /**
   * Cyber alert alarm pulse for threat detection
   */
  public playThreatAlert(): void {
    if (!this.init() || !this.ctx) return;
    try {
      const frequencies = [440, 310, 220];
      const baseTime = this.ctx.currentTime;
      frequencies.forEach((freq, idx) => {
        const osc = this.ctx!.createOscillator();
        const gain = this.ctx!.createGain();
        const t = baseTime + idx * 0.09;
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(freq, t);

        gain.gain.setValueAtTime(0.035, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.16);

        osc.connect(gain);
        gain.connect(this.ctx!.destination);
        osc.start(t);
        osc.stop(t + 0.16);
      });
    } catch {}
  }

  /**
   * Caution warning chirp for parked or unverified domains
   */
  public playWarningChirp(): void {
    if (!this.init() || !this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const t = this.ctx.currentTime;
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(600, t);
      osc.frequency.setValueAtTime(450, t + 0.08);

      gain.gain.setValueAtTime(0.03, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.2);

      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(t);
      osc.stop(t + 0.2);
    } catch {}
  }
}

export const cyberAudio = new CyberAudioSynthesizer();
