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
        // Button text varies by status; just check it exists
        const btn = document.querySelector('.btn-primary');
        expect(btn).not.toBeNull();
    });

    it('renders demo section title', () => {
        render(<App />);
        expect(screen.getByText('🚀 Demo Scenarios')).toBeInTheDocument();
    });

    it('renders Doctor Login and Pharmacy demo buttons', () => {
        render(<App />);
        // The actual rendered button IDs exist in the DOM
        expect(document.getElementById('btn-doctor-login')).not.toBeNull();
        expect(document.getElementById('btn-pharmacy')).not.toBeNull();
        expect(document.getElementById('btn-ehds-er')).not.toBeNull();
        expect(document.getElementById('btn-liquor-store')).not.toBeNull();
    });
});
