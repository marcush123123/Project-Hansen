import { useEffect, useRef, useState } from 'react';

export interface ExportOption {
  label: string;
  format: string;
  onSelect: () => void | Promise<void>;
}

export default function ExportMenu({ options, disabled = false, busy = false }: { options: ExportOption[]; disabled?: boolean; busy?: boolean }) {
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const dismiss = (event: MouseEvent) => {
      if (!menu.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', dismiss);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('mousedown', dismiss);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);

  useEffect(() => { if (disabled || busy) setOpen(false); }, [disabled, busy]);

  return <div className="export-menu" ref={menu}>
    <button className="primary export-trigger" type="button" disabled={disabled || busy} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(value => !value)}>
      {busy ? 'Exporting…' : 'Export'} <span aria-hidden="true">⌄</span>
    </button>
    {open && <div className="export-options" role="menu" aria-label="Export format">
      {options.map(option => <button key={option.format} type="button" role="menuitem" onClick={() => { setOpen(false); void option.onSelect(); }}>
        <span>{option.label}</span><small>{option.format.toUpperCase()}</small>
      </button>)}
    </div>}
  </div>;
}
