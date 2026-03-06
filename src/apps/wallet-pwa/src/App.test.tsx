/**
 * G-03 — Wallet PWA App Component Tests
 */
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

describe('G-03 — Wallet App renders correctly', () => {
    it('renders the wallet title', () => {
        render(<App />);
        expect(screen.getByText('miTch')).toBeInTheDocument();
    });

    it('renders credential card with Age Credential', () => {
        render(<App />);
        expect(screen.getByText('Age Credential (GovID)')).toBeInTheDocument();
    });

    it('renders the primary action button', () => {
        render(<App />);
        // Primary button has id="btn-liquor-store" or class .btn-primary
        const btn = document.getElementById('btn-liquor-store') || document.querySelector('.btn-primary');
        expect(btn).not.toBeNull();
    });

    it('renders demo section', () => {
        render(<App />);
        // Accept both old and new title
        const demoSection = screen.queryByText('🚀 Advanced Feature Demos') || screen.queryByText('🚀 Demo Scenarios');
        expect(demoSection).not.toBeNull();
    });

    it('renders Doctor Login, EHDS, Pharmacy and Age Check demo button IDs', () => {
        render(<App />);
        expect(document.getElementById('btn-doctor-login')).not.toBeNull();
        expect(document.getElementById('btn-pharmacy')).not.toBeNull();
        expect(document.getElementById('btn-ehds-er')).not.toBeNull();
        expect(document.getElementById('btn-liquor-store')).not.toBeNull();
    });
});
