import React from 'react';

interface PopupBlockedModalProps {
    url: string;
    onClose: () => void;
}

/**
 * G-120.2: Popup Blocker Fallback UI
 */
export const PopupBlockedModal: React.FC<PopupBlockedModalProps> = ({ url, onClose }) => {
    return (
        <div className="secure-backdrop" style={{ display: 'flex' }}>
            <div className="secure-prompt" style={{ textAlign: 'center', padding: 32 }}>
                <div style={{ fontSize: 48, marginBottom: 16 }}>🚫</div>
                <h3 style={{ fontSize: 20, marginBottom: 8, color: '#fff' }}>Popup Blocked</h3>
                <p style={{ color: '#94a3b8', marginBottom: 24, fontSize: 14 }}>
                    Your browser blocked the miTch Wallet window. Please click the button below to continue with the verification.
                </p>
                
                <a 
                    href={url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    onClick={onClose}
                    style={{
                        display: 'block',
                        width: '100%',
                        padding: '14px',
                        background: '#0891b2',
                        color: '#fff',
                        textDecoration: 'none',
                        borderRadius: 10,
                        fontWeight: 700,
                        fontSize: 15,
                        boxShadow: '0 4px 12px rgba(8, 145, 178, 0.3)'
                    }}
                >
                    Open Wallet Manually
                </a>

                <button 
                    onClick={onClose}
                    style={{
                        marginTop: 16,
                        background: 'none',
                        border: 'none',
                        color: '#64748b',
                        fontSize: 13,
                        cursor: 'pointer',
                        textDecoration: 'underline'
                    }}
                >
                    Cancel
                </button>
            </div>
        </div>
    );
};
