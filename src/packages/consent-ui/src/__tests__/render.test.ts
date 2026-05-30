import { describe, expect, it } from 'vitest';
import { clear, el } from '../render';

describe('render helpers', () => {
    it('renders text via textContent, never innerHTML', () => {
        const malicious = '<img src=x onerror=alert(1)>';
        const node = el(document, 'span', { text: malicious });
        expect(node.textContent).toBe(malicious);
        // No actual <img> element should exist as a child.
        expect(node.querySelector('img')).toBeNull();
        expect(node.children.length).toBe(0);
    });

    it('sets class, role, aria-label, dataset, and arbitrary attributes', () => {
        const node = el(document, 'button', {
            class: 'btn primary',
            role: 'button',
            ariaLabel: 'Approve',
            dataset: { action: 'approve' },
            attrs: { type: 'button' },
        });
        expect(node.className).toBe('btn primary');
        expect(node.getAttribute('role')).toBe('button');
        expect(node.getAttribute('aria-label')).toBe('Approve');
        expect(node.dataset.action).toBe('approve');
        expect(node.getAttribute('type')).toBe('button');
    });

    it('appends children in order', () => {
        const child1 = el(document, 'span', { text: 'a' });
        const child2 = el(document, 'span', { text: 'b' });
        const parent = el(document, 'div', {}, [child1, 'middle', child2]);
        expect(parent.childNodes.length).toBe(3);
        expect(parent.textContent).toBe('amiddleb');
    });

    it('clear removes all children', () => {
        const parent = el(document, 'div', {}, [
            el(document, 'span', { text: 'x' }),
            el(document, 'span', { text: 'y' }),
        ]);
        expect(parent.childNodes.length).toBe(2);
        clear(parent);
        expect(parent.childNodes.length).toBe(0);
    });
});
