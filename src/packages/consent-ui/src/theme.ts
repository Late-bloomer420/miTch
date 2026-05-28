import type { ConsentTheme } from './types';

export const DEFAULT_THEME: Required<ConsentTheme> = {
    colorBg: '#0b0d12',
    colorSurface: '#11141b',
    colorBorder: '#1f2430',
    colorText: '#e6e8ec',
    colorMuted: '#7a8090',
    colorAllow: '#4ade80',
    colorWithhold: '#fbbf24',
    colorDeny: '#f87171',
    colorAccent: '#7c8cff',
    radius: '10px',
    fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
};

export function mergeTheme(override?: ConsentTheme | null): Required<ConsentTheme> {
    if (!override) return DEFAULT_THEME;
    return { ...DEFAULT_THEME, ...override };
}

export function themeToCssVars(theme: Required<ConsentTheme>): string {
    return [
        `--mc-bg:${theme.colorBg}`,
        `--mc-surface:${theme.colorSurface}`,
        `--mc-border:${theme.colorBorder}`,
        `--mc-text:${theme.colorText}`,
        `--mc-muted:${theme.colorMuted}`,
        `--mc-allow:${theme.colorAllow}`,
        `--mc-withhold:${theme.colorWithhold}`,
        `--mc-deny:${theme.colorDeny}`,
        `--mc-accent:${theme.colorAccent}`,
        `--mc-radius:${theme.radius}`,
        `--mc-font:${theme.fontFamily}`,
    ].join(';');
}
