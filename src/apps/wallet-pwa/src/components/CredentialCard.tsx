// TODO(backlog E-45 / V-03): Branded credential card (renders via CredentialRenderer).
// Implemented but not yet wired into the wallet UI (no live importer). See
// docs/BACKLOG.md "Phase 5 — Visual & Branding". Do not delete: parked, pending wiring.
import React from 'react';
import { CredentialRenderer, RenderMethod } from './CredentialRenderer';

interface CredentialCardProps {
    id: string;
    name: string;
    issuer: string;
    claims: Record<string, unknown>;
    renderMethod?: RenderMethod[];
}

export const CredentialCard: React.FC<CredentialCardProps> = ({
    name,
    issuer,
    claims,
    renderMethod
}) => {
    return (
        <div className="mitch-credential-card-wrapper" style={{ marginBottom: '16px' }}>
            {renderMethod && renderMethod.length > 0 ? (
                <CredentialRenderer 
                    claims={{ 
                        ...claims, 
                        credentialName: name, 
                        issuerName: issuer 
                    }} 
                    renderMethods={renderMethod} 
                    fallbackName={name} 
                />
            ) : (
                <div className="credential-item">
                    <span className="credential-icon">🪪</span>
                    <div>
                        <div className="credential-name">{name}</div>
                        <div className="credential-issuer">{issuer}</div>
                    </div>
                </div>
            )}
        </div>
    );
};
