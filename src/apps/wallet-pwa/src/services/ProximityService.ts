/**
 * ProximityService.ts
 *
 * Handles ISO 18013-5 Proximity Presentation (BLE/NFC).
 * Currently implemented with a Mock Adapter for demonstration.
 */

import { 
    buildDeviceEngagement, 
    createEngagementUri 
} from '@askmi/mdoc';

export interface ProximitySession {
    engagementUri: string;
    onConnected: () => void;
    onMessage: (msg: any) => void;
    send: (msg: any) => void;
    close: () => void;
}

export class ProximityService {
    /**
     * Start a new proximity session.
     * Generates a QR-ready URI and initializes the mock transport.
     */
    static async startSession(devicePublicKey: CryptoKey): Promise<ProximitySession> {
        const engagementBytes = await buildDeviceEngagement(devicePublicKey);
        const engagementUri = createEngagementUri(engagementBytes);

        let connectedCallback = () => {};
        let messageCallback = (_msg: any) => {};

        // Mock Transport Logic
        const session: ProximitySession = {
            engagementUri,
            onConnected: () => {}, // To be set by caller
            onMessage: () => {},   // To be set by caller
            send: (msg: any) => {
                console.info('[ProximityMock] Sending to Reader:', msg);
                // Simulate Reader response after 1 second
                if (msg.type === 'device_response') {
                    console.info('[ProximityMock] Presentation complete.');
                }
            },
            close: () => {
                console.info('[ProximityMock] Session closed.');
            }
        };

        // Simulate a reader connecting after 3 seconds of showing the QR
        setTimeout(() => {
            console.info('[ProximityMock] Reader connected!');
            if (session.onConnected) session.onConnected();
            
            // Simulate receiving a DeviceRequest
            setTimeout(() => {
                const mockRequest = {
                    type: 'device_request',
                    items: [
                        { ns: 'org.iso.18013.5.1', element: 'given_name' },
                        { ns: 'org.iso.18013.5.1', element: 'family_name' }
                    ]
                };
                console.info('[ProximityMock] Received DeviceRequest');
                if (session.onMessage) session.onMessage(mockRequest);
            }, 1000);
        }, 3000);

        return session;
    }
}
