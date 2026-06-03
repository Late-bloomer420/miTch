import React, { useEffect, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { ProximityService, ProximitySession } from '../services/ProximityService';
import { WalletService } from '../services/WalletService';

interface ProximityViewProps {
    wallet: WalletService;
    onComplete: () => void;
    onCancel: () => void;
}

export const ProximityView: React.FC<ProximityViewProps> = ({ wallet, onComplete, onCancel }) => {
    const [session, setSession] = useState<ProximitySession | null>(null);
    const [status, setStatus] = useState<'INITIALIZING' | 'SHOWING_QR' | 'CONNECTED' | 'PRESENTING' | 'COMPLETE'>('INITIALIZING');

    useEffect(() => {
        let activeSession: ProximitySession | null = null;

        const init = async () => {
            const pubKey = wallet.getIdentityPublicKey();
            if (!pubKey) {
                console.error('Wallet identity key not initialized');
                onCancel();
                return;
            }

            const sess = await ProximityService.startSession(pubKey);
            activeSession = sess;
            
            sess.onConnected = () => {
                setStatus('CONNECTED');
            };

            sess.onMessage = async (msg) => {
                if (msg.type === 'device_request') {
                    setStatus('PRESENTING');
                    
                    try {
                        // 1. Generate real ISO 18013-5 response from WalletService
                        const responseBytes = await wallet.generateProximityResponse(
                            'mdoc-mdl-001', // Seed mDL
                            msg.items,
                            [null, null, null] // SessionTranscript placeholder
                        );

                        setTimeout(() => {
                            sess.send({ 
                                type: 'device_response', 
                                data: btoa(String.fromCharCode(...responseBytes)) 
                            });
                            setStatus('COMPLETE');
                            setTimeout(onComplete, 2000);
                        }, 1500);
                    } catch (err) {
                        console.error('Failed to generate proximity response:', err);
                        onCancel();
                    }
                }
            };

            setSession(sess);
            setStatus('SHOWING_QR');
        };

        init();

        return () => {
            if (activeSession) activeSession.close();
        };
    }, [wallet, onComplete, onCancel]);

    return (
        <div className="proximity-view">
            <div className="proximity-card">
                <button className="proximity-close" onClick={onCancel}>✕</button>
                
                <h2 className="proximity-title">Proximity Presentation</h2>
                <p className="proximity-subtitle">ISO 18013-5 Offline Flow</p>

                <div className="proximity-content">
                    {status === 'INITIALIZING' && <div className="proximity-loader">Initializing...</div>}

                    {status === 'SHOWING_QR' && session && (
                        <div className="proximity-qr-container">
                            <div className="proximity-qr-frame">
                                <QRCodeSVG value={session.engagementUri} size={200} />
                            </div>
                            <p className="proximity-instruction">Scan with mdoc reader</p>
                            <div className="proximity-uri-debug">{session.engagementUri.substring(0, 30)}...</div>
                        </div>
                    )}

                    {status === 'CONNECTED' && (
                        <div className="proximity-status-box">
                            <div className="proximity-icon connected">🤝</div>
                            <p>Reader connected!</p>
                            <p className="small">Waiting for request...</p>
                        </div>
                    )}

                    {status === 'PRESENTING' && (
                        <div className="proximity-status-box">
                            <div className="proximity-icon presenting">📤</div>
                            <p>Sending mDL data...</p>
                            <div className="proximity-progress-bar">
                                <div className="proximity-progress-inner"></div>
                            </div>
                        </div>
                    )}

                    {status === 'COMPLETE' && (
                        <div className="proximity-status-box">
                            <div className="proximity-icon complete">✅</div>
                            <p>Presentation Successful</p>
                            <p className="small">Transaction logged.</p>
                        </div>
                    )}
                </div>

                <div className="proximity-footer">
                    <span className="proximity-security-badge">🛡️ End-to-End Encrypted</span>
                </div>
            </div>
        </div>
    );
};
