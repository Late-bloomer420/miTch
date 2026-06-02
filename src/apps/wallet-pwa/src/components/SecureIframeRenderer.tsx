import React from 'react';

interface SecureIframeRendererProps {
    /** The rendered SVG content to display */
    content: string;
}

/**
 * V-02: Sandboxed Iframe Renderer
 * 
 * Provides an isolated environment for rendering credential templates.
 * Enforces strict CSP and HTML5 Sandbox to prevent:
 * - Tracking pixels / remote data leakage
 * - Script injection / XSS
 * - CSS-based side-channel attacks
 */
export const SecureIframeRenderer: React.FC<SecureIframeRendererProps> = ({ content }) => {
    // Generate a minimal HTML wrapper with strict CSP
    const srcDoc = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';">
            <style>
                body { margin: 0; padding: 0; overflow: hidden; display: flex; justify-content: center; align-items: center; background: transparent; }
                svg { width: 100%; height: auto; max-height: 100vh; }
            </style>
        </head>
        <body>
            ${content}
        </body>
        </html>
    `;

    return (
        <iframe
            title="Credential Proof Visual"
            srcDoc={srcDoc}
            sandbox="" // Strictest sandbox: no scripts, no forms, no same-origin
            style={{
                width: '100%',
                height: '240px', // Standard card aspect ratio roughly
                border: 'none',
                borderRadius: '8px',
                overflow: 'hidden',
                background: 'transparent'
            }}
        />
    );
};
