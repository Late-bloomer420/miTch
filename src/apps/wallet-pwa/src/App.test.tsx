import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import App from './App';
import '@testing-library/jest-dom'; // Note: usually setup in a setup file, but explicit here for PoC simplicity

// Mock crypto since jsdom doesn't have full WebCrypto
Object.defineProperty(global, 'crypto', {
    value: {
        subtle: {
            digest: async () => new Uint8Array([1, 2, 3])
        }
    }
});

describe('Wallet PWA App', () => {
    it('renders the title', () => {
        render(<App />);
        expect(screen.getByText('miTch Wallet PoC')).toBeInTheDocument();
    });

    it('checks health and displays WebCrypto success', async () => {
        render(<App />);
        // Initial state
        expect(screen.getByText(/Checking.../i)).toBeInTheDocument();

        // After async check
        await waitFor(() => {
            expect(screen.getByText(/✓ Wallet Ready – WebCrypto Available/i)).toBeInTheDocument();
        });
    });
});
