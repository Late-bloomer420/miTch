import React, { useState } from 'react';
import { DocumentService, ProofOfExistence } from '../services/DocumentService';

interface SignedDocument {
    proof: ProofOfExistence;
    proofToken: string;
    signedAt: string;
}

interface DocumentsTabProps {
    onSign: (payload: ProofOfExistence) => Promise<{ proofToken: string; auditLog: string[] }>;
}

export const DocumentsTab: React.FC<DocumentsTabProps> = ({ onSign }) => {
    const [signedDocs, setSignedDocs] = useState<SignedDocument[]>([]);
    const [isDragging, setIsDragging] = useState(false);
    const [processing, setProcessing] = useState(false);

    const handleFile = async (file: File) => {
        setProcessing(true);
        try {
            const hash = await DocumentService.hashFile(file);
            const payload = DocumentService.createProofOfExistence(hash, file, file.name);

            const { proofToken, auditLog } = await onSign(payload);

            setSignedDocs(prev => [...prev, {
                proof: payload,
                proofToken,
                signedAt: new Date().toISOString()
            }]);

            console.log('✅ Document signed successfully:', auditLog);
        } catch (error) {
            console.error('❌ Signing failed:', error);
            alert(`Signing failed: ${error}`);
        } finally {
            setProcessing(false);
        }
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);

        const file = e.dataTransfer.files[0];
        if (file) {
            handleFile(file);
        }
    };

    const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            handleFile(file);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <h2>📄 Document Signing</h2>
            <p style={{ color: '#666', marginBottom: '20px' }}>
                Sign any document to create a cryptographic proof of existence. The file never leaves your device.
            </p>

            <div
                onDrop={handleDrop}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                style={{
                    border: `2px dashed ${isDragging ? '#4CAF50' : '#ccc'}`,
                    borderRadius: '8px',
                    padding: '40px',
                    textAlign: 'center',
                    backgroundColor: isDragging ? '#f0f8f0' : '#fafafa',
                    marginBottom: '30px',
                    cursor: 'pointer'
                }}
            >
                {processing ? (
                    <div>⏳ Processing...</div>
                ) : (
                    <>
                        <div style={{ fontSize: '48px', marginBottom: '10px' }}>📎</div>
                        <div>Drag & Drop a file here</div>
                        <div style={{ margin: '10px 0', color: '#999' }}>or</div>
                        <label style={{
                            padding: '10px 20px',
                            backgroundColor: '#2196F3',
                            color: 'white',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            display: 'inline-block'
                        }}>
                            Choose File
                            <input
                                type="file"
                                onChange={handleFileInput}
                                style={{ display: 'none' }}
                            />
                        </label>
                    </>
                )}
            </div>

            <h3>Signed Documents ({signedDocs.length})</h3>
            {signedDocs.length === 0 ? (
                <p style={{ color: '#999', fontStyle: 'italic' }}>No documents signed yet.</p>
            ) : (
                <div>
                    {signedDocs.map((doc, idx) => (
                        <div key={idx} style={{
                            border: '1px solid #ddd',
                            borderRadius: '4px',
                            padding: '15px',
                            marginBottom: '10px',
                            backgroundColor: '#fff'
                        }}>
                            <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>
                                {doc.proof.description}
                            </div>
                            <div style={{ fontSize: '12px', color: '#666' }}>
                                <div>📝 Hash: <code>{doc.proof.hash.substring(0, 16)}...</code></div>
                                <div>🔐 Algorithm: {doc.proof.hashAlg}</div>
                                <div>📄 Type: {doc.proof.mediaType}</div>
                                <div>⏰ Signed: {new Date(doc.signedAt).toLocaleString()}</div>
                            </div>
                            <details style={{ marginTop: '10px' }}>
                                <summary style={{ cursor: 'pointer', color: '#2196F3' }}>View Proof Token</summary>
                                <pre style={{
                                    backgroundColor: '#f5f5f5',
                                    padding: '10px',
                                    borderRadius: '4px',
                                    fontSize: '10px',
                                    overflow: 'auto',
                                    marginTop: '5px'
                                }}>
                                    {doc.proofToken}
                                </pre>
                            </details>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};
