import React, { useMemo } from 'react';
import Mustache from 'mustache';

export interface RenderMethod {
    id: string;
    type: string;
    format?: string;
    digestMultibase?: string;
}

interface CredentialRendererProps {
    /** The credential payload (claims) */
    claims: Record<string, unknown>;
    /** The render method hints from the VC */
    renderMethods?: RenderMethod[];
    /** Fallback name if no template is available */
    fallbackName: string;
}

/**
 * W3C VC-Render compliant credential renderer.
 * Supports:
 * - svg-mustache: Renders a remote SVG template with credential data.
 * - Local fallback: Standard card UI.
 * 
 * SECURITY NOTE:
 * Templates should ideally be fetched from a trusted source and 
 * verified against digestMultibase. For this PoC, we use a simple fetch.
 */
export const CredentialRenderer: React.FC<CredentialRendererProps> = ({ 
    claims, 
    renderMethods, 
    fallbackName 
}) => {
    const svgTemplateMethod = renderMethods?.find(m => m.format === 'svg-mustache');

    const [svgContent, setSvgContent] = React.useState<string | null>(null);
    const [error, setError] = React.useState<string | null>(null);

    React.useEffect(() => {
        if (svgTemplateMethod) {
            fetch(svgTemplateMethod.id)
                .then(res => {
                    if (!res.ok) throw new Error(`Template fetch failed: ${res.status}`);
                    return res.text();
                })
                .then(async template => {
                    if (svgTemplateMethod.digestMultibase) {
                        await verifyDigestMultibase(template, svgTemplateMethod.digestMultibase);
                    }
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
            <div 
                className="mitch-credential-svg"
                dangerouslySetInnerHTML={{ __html: svgContent }}
                style={{ width: '100%', height: 'auto', borderRadius: '8px', overflow: 'hidden' }}
            />
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
