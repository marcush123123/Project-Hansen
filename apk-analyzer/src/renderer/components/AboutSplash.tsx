import { useEffect, useRef } from 'react';
import hansenLogo from '../../../assets/logo.png';

const GITHUB = 'https://github.com/marcush123123/Project-Hansen';
const RELEASES = `${GITHUB}/releases`;
export default function AboutSplash({ onClose }: { onClose: () => void }) {
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    close.current?.focus();
    const key = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', key); return () => window.removeEventListener('keydown', key);
  }, [onClose]);
  return <div className="about-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}><section className="about-splash" role="dialog" aria-modal="true" aria-labelledby="about-title">
    <button ref={close} type="button" className="about-close" onClick={onClose} aria-label="Close About Hansen">×</button>
    <img className="about-mark" src={hansenLogo} alt="Hansen logo"/><p className="eyebrow">ABOUT THE APPLICATION</p><h1 id="about-title">Hansen</h1><p className="about-version">Version {__APP_VERSION__}</p>
    <p className="about-description">A local desktop application for inspecting Android APK and XAPK packages, comparing releases, and presenting security, privacy, signing, and reputation evidence without installing the application.</p>
    <div className="about-credit"><strong>Created by Marcus Hopps</strong><p>Hansen was created with the assistance of artificial intelligence.</p></div>
    <p className="about-license"><strong>License</strong><br/>Apache License 2.0</p>
    <div className="about-links"><button className="secondary" onClick={() => window.api.openExternal(GITHUB)}>GitHub repository ↗</button><button className="primary" onClick={() => window.api.openExternal(RELEASES)}>Update notes ↗</button></div>
  </section></div>;
}
