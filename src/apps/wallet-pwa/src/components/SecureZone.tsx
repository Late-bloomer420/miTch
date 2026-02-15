
import React, { useRef, useEffect, useState } from 'react';

interface SecureZoneProps {
    children: React.ReactNode;
    onIntervention: (reason: string) => void;
    className?: string;
}

/**
 * T-37: Overlay-Detection Engine (Visual Auditor)
 * 
 * This component wraps high-security UI elements (like "Confirm Transaction" or "Delete Key").
 * It performs runtime checks to ensure the element isn't being spoofed, covered, or redressed
 * by malicious overlays (Clickjacking/UI Redress).
 */
export const SecureZone: React.FC<SecureZoneProps> = ({ children, onIntervention, className }) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const [isSecure, setIsSecure] = useState(true);

    /**
     * Core Detection Logic:
     * Checks if the center of the secure element is occluded by another element.
     */
    const checkOverlay = () => {
        if (!containerRef.current) return;

        const rect = containerRef.current.getBoundingClientRect();

        // 1. Visibility Check
        if (rect.width === 0 || rect.height === 0) return; // Hidden, so strictly "safe" (cannot be clicked)

        // 2. Center Point Sampling
        const x = rect.left + rect.width / 2;
        const y = rect.top + rect.height / 2;

        // What is the browser actually rendering on top at this pixel?
        const topElement = document.elementFromPoint(x, y);

        if (!topElement) return;

        // Is the top element our container or inside it?
        const isSelfOrChild = containerRef.current === topElement || containerRef.current.contains(topElement);

        if (!isSelfOrChild) {
            // SECURITY VIOLATION: Something is on top of us!
            console.warn(`[SecureZone] Overlay Detected! Blocked by:`, topElement);
            setIsSecure(false);
            onIntervention('OVERLAY_DETECTED');
        } else {
            if (!isSecure) setIsSecure(true);
        }
    };

    /**
     * T-37: Opacity & Redress Check (Simplified)
     * Detects if the element itself is being made transparent to trick the user (Invisible Overlay)
     */
    const checkStyles = () => {
        if (!containerRef.current) return;
        const style = window.getComputedStyle(containerRef.current);

        if (parseFloat(style.opacity) < 0.9) {
            // Too transparent - potential clickjacking trap
            setIsSecure(false);
            onIntervention('OPACITY_TOO_LOW');
        }
    };

    useEffect(() => {
        // Continuous Audit Loop (Low Frequency for Performance)
        const interval = setInterval(() => {
            checkOverlay();
            checkStyles();
        }, 1000);

        // Immediate check on mount
        checkOverlay();

        // Check on likely resize/scroll events
        window.addEventListener('resize', checkOverlay);
        window.addEventListener('scroll', checkOverlay, true);

        return () => {
            clearInterval(interval);
            window.removeEventListener('resize', checkOverlay);
            window.removeEventListener('scroll', checkOverlay, true);
        };
    }, []);

    // Intercept clicks if compromised
    const handleCapture = (e: React.MouseEvent) => {
        // Perform a strict check immediately before allowing the click
        checkOverlay(); // Update state synchronously if possible (React updates are batched, so we rely on the logic below)

        // Manual check again to be safe
        if (!containerRef.current) return;
        const rect = containerRef.current.getBoundingClientRect();
        const topElement = document.elementFromPoint(e.clientX, e.clientY);
        const isSelfOrChild = containerRef.current === topElement || containerRef.current.contains(topElement as Node);

        if (!isSelfOrChild) {
            e.preventDefault();
            e.stopPropagation();
            onIntervention('JUST_IN_TIME_OVERLAY_BLOCK');
            return;
        }

        if (!isSecure) {
            e.preventDefault();
            e.stopPropagation();
            alert('Security Alert: Interaction Blocked due to detected UI interference.');
        }
    };

    return (
        <div
            ref={containerRef}
            className={`${className || ''} ${!isSecure ? 'security-lockdown' : ''}`}
            onClickCapture={handleCapture}
            style={!isSecure ? { border: '2px solid red', pointerEvents: 'none', opacity: 0.5 } : {}}
        >
            {/* Visual Indicator of Security Zone */}
            <div style={{ position: 'absolute', top: -10, right: -10, fontSize: '10px', color: isSecure ? 'green' : 'red' }}>
                {isSecure ? '🛡️' : '⛔'}
            </div>
            {children}
        </div>
    );
};
