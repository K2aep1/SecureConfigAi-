import type { CSSProperties } from 'react';
import '../brand.css';

export type SecureConfigAILogoProps = {
  /** Use dark on the dark sidebar, light on white/light surfaces. */
  tone?: 'dark' | 'light';
  size?: 'sm' | 'md' | 'lg';
  /** Hide the wordmark and render only the icon. */
  compact?: boolean;
  /** Optional product descriptor shown under the wordmark. */
  subtitle?: string;
  className?: string;
};

const markSizes: Record<NonNullable<SecureConfigAILogoProps['size']>, number> = {
  sm: 30,
  md: 40,
  lg: 48,
};

/** Branded, dependency-free SecureConfigAI logo component. */
export function SecureConfigAILogo({
  tone = 'dark',
  size = 'md',
  compact = false,
  subtitle = 'Endpoint security platform',
  className = '',
}: SecureConfigAILogoProps) {
  const markSize = markSizes[size];

  return (
    <div
      className={`sc-brand-logo sc-brand-logo--${tone} sc-brand-logo--${size}${compact ? ' sc-brand-logo--compact' : ''} ${className}`.trim()}
      aria-label="SecureConfigAI"
      role="img"
    >
      <svg
        className="sc-brand-logo__mark"
        width={markSize}
        height={markSize}
        viewBox="0 0 48 48"
        fill="none"
        aria-hidden="true"
        focusable="false"
        style={{ flex: `0 0 ${markSize}px` } as CSSProperties}
      >
        <rect width="48" height="48" rx="12" fill="#10243E" />
        <path
          d="M24 7.5 36.2 12v10.2c0 7.5-4.9 13.2-12.2 17.1-7.3-3.9-12.2-9.6-12.2-17.1V12L24 7.5Z"
          stroke="#F2F7FF"
          strokeWidth="2.1"
          strokeLinejoin="round"
        />
        <path d="M16.8 19.1h14.4M16.8 24h14.4M16.8 28.9h14.4" stroke="#45E0CF" strokeWidth="2" strokeLinecap="round" />
        <circle cx="21" cy="19.1" r="1.8" fill="#10243E" stroke="#45E0CF" strokeWidth="1.6" />
        <circle cx="27.4" cy="24" r="1.8" fill="#10243E" stroke="#45E0CF" strokeWidth="1.6" />
        <circle cx="19.3" cy="28.9" r="1.8" fill="#10243E" stroke="#45E0CF" strokeWidth="1.6" />
      </svg>

      {!compact && (
        <span className="sc-brand-logo__copy">
          <span className="sc-brand-logo__wordmark">
            <span>SecureConfig</span><span className="sc-brand-logo__ai">AI</span>
          </span>
          {subtitle && <span className="sc-brand-logo__subtitle">{subtitle}</span>}
        </span>
      )}
    </div>
  );
}
