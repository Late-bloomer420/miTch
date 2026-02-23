import { chromium, Browser, LaunchOptions } from 'playwright';

/**
 * Configuration for the "Mitch Secure Sandbox"
 * 
 * Enforces a hardware-independent rendering environment using Google SwiftShader.
 * This ensures that:
 * 1. Rendering is deterministic (pixel-perfect match across devices).
 * 2. GPU side-channel attacks are mitigated (no physical GPU used).
 * 3. Text rendering is normalized (no subpixel anti-aliasing).
 */
export const SWIFTSHADER_ARGS = [
    // Force software rendering via SwiftShader
    '--use-gl=swiftshader',
    '--disable-gpu',

    // Deterministic Font Rendering (Critical for Context Pinning)
    '--font-render-hinting=none',
    '--disable-font-subpixel-positioning',
    '--disable-lcd-text',

    // Security Hardening
    '--disable-extensions',
    '--no-sandbox', // Often needed for CI, assess risk for local
    '--disable-dev-shm-usage'
];

/**
 * Launch a browser instance in the Secure UI Sandbox.
 */
export async function launchSecureBrowser(options: LaunchOptions = {}): Promise<Browser> {
    console.log('🛡️  Launching Secure UI Sandbox (SwiftShader Mode)...');

    return chromium.launch({
        ...options,
        args: [
            ...(options.args || []),
            ...SWIFTSHADER_ARGS
        ]
    });
}
