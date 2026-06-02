import React, { useState, useEffect } from 'react';
import Mustache from 'mustache';
import { verifyDigestMultibase } from '@mitch/shared-crypto';
import { SecureIframeRenderer } from './SecureIframeRenderer';

export interface RenderMethod {
    id: string;
    type: string;
    format?: string;
    digestMultibase?: string;
}

interface CredentialRendererProps {
    renderMethods?: RenderMethod[];
    claims: Record<string, unknown>;
    fallbackName?: string;
}

/**
 * Enhanced Credential Renderer (v1.0.1 Patch)
 * 
 * Securely renders credential visual templates (SVG) with:
 * 1. Cryptographic integrity check (V-04)
 * 2. Strict Sandboxed Iframe isolation (V-02)
 */
export const CredentialRenderer: React.FC<CredentialRendererProps> = ({
    renderMethods = [],
    claims,
    fallbackName = 'Verifiable Credential'
}) => {
    const [svgContent, setSvgContent] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const svgTemplateMethod = renderMethods.find(m => m.type === 'SvgTemplate');

    useEffect(() => {
        if (svgTemplateMethod) {
            fetch(svgTemplateMethod.id)
                .then(async res => {
                    if (!res.ok) throw new Error(`HTTP ${res.status}`);
                    return res.text();
                })
                .then(async template => {
                    // V-04: Verify cryptographic digest of the remote template
                    if (svgTemplateMethod.digestMultibase) {
                        try {
                            await verifyDigestMultibase(template, svgTemplateMethod.digestMultibase);
                        } catch (e) {
                            console.error('V-04 Integrity Violation:', e);
                            throw new Error('TEMPLATE_INTEGRITY_FAILED');
                        }
                    }

                    // Render with mustache
                    const rendered = Mustache.render(template, claims);
                    setSvgContent(rendered);
                })
                .catch(err => {
                    console.error('Render error:', err);
                    setError(err.message);
                });
        }
    }, [svgTemplateMethod, claims]);

    if (svgContent) {
        return (
            <SecureIframeRenderer content={svgContent} />
        );
    }

    return (
        <div className="credential-item">
            <span className="credential-icon">🪪</span>
            <div>
                <div className="credential-name">{fallbackName}</div>
                <div className="credential-issuer">{error ? `Error: ${error}` : 'did:example:issuer'}</div>
            </div>
        </div>
    );
};
