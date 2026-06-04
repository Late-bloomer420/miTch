import { beforeAll, describe, expect, it } from 'vitest';
import {
    CONSENT_CANCEL_EVENT,
    CONSENT_ELEMENT_TAG,
    CONSENT_EVENT,
    ConsentElement,
    defineConsentElement,
} from '../consent-element';
import type { ConsentRequest } from '../types';

beforeAll(() => {
    defineConsentElement();
});

function makeRequest(overrides: Partial<ConsentRequest> = {}): ConsentRequest {
    return {
        requestId: 'req-1',
        verifier: { id: 'did:askmi:verifier-x', displayName: "Joe's" },
        purpose: 'Age verification',
        claims: [
            { key: 'age', policyState: 'requested' },
            { key: 'name', policyState: 'denied' },
        ],
        predicates: [
            {
                id: 'pred_0_age_gte',
                claim: 'age',
                operation: 'gte',
                value: 18,
                policyState: 'allowed',
            },
        ],
        ...overrides,
    };
}

function mount(): ConsentElement {
    const node = document.createElement(CONSENT_ELEMENT_TAG) as ConsentElement;
    document.body.appendChild(node);
    return node;
}

function shadow(node: ConsentElement): ShadowRoot {
    const root = node.shadowRoot;
    if (!root) throw new Error('shadowRoot missing');
    return root;
}

function queryItem(root: ShadowRoot, key: string): HTMLElement {
    const el = root.querySelector<HTMLElement>(`.item[data-key="${key}"]`);
    if (!el) throw new Error(`item not found: ${key}`);
    return el;
}

describe('<mitch-consent>', () => {
    it('registers under the expected tag', () => {
        expect(customElements.get(CONSENT_ELEMENT_TAG)).toBeDefined();
    });

    it('renders the title, verifier, purpose, claims and predicates', () => {
        const node = mount();
        node.request = makeRequest();
        const root = shadow(node);
        const text = root.textContent ?? '';
        expect(text).toContain('Consent required');
        expect(text).toContain("Joe's");
        expect(text).toContain('Age verification');
        expect(root.querySelectorAll('.item[data-kind="claim"]').length).toBe(2);
        expect(root.querySelectorAll('.item[data-kind="predicate"]').length).toBe(1);
    });

    it('renders denied claim as non-toggleable with a denied badge', () => {
        const node = mount();
        node.request = makeRequest();
        const root = shadow(node);
        const nameItem = queryItem(root, 'name');
        expect(nameItem.dataset.denied).toBe('true');
        const toggle = nameItem.querySelector<HTMLButtonElement>('.toggle');
        expect(toggle?.disabled).toBe(true);
        expect(nameItem.querySelector('.state.denied')).not.toBeNull();
    });

    it('defaults raw claims to withheld (fail-closed) and toggles to allowed on click', () => {
        const node = mount();
        node.request = makeRequest();
        const root = shadow(node);
        const ageItem = queryItem(root, 'age');
        // Initial: withheld
        expect(ageItem.querySelector('.state.withheld')).not.toBeNull();
        const toggle = ageItem.querySelector<HTMLButtonElement>('.toggle');
        expect(toggle?.getAttribute('aria-pressed')).toBe('false');
        toggle?.click();
        // After click, re-query (render replaces the tree)
        const root2 = shadow(node);
        const ageItem2 = queryItem(root2, 'age');
        expect(ageItem2.querySelector('.state.allowed')).not.toBeNull();
        const toggle2 = ageItem2.querySelector<HTMLButtonElement>('.toggle');
        expect(toggle2?.getAttribute('aria-pressed')).toBe('true');
    });

    it('predicates marked allowed by policy start in the allowed state', () => {
        const node = mount();
        node.request = makeRequest();
        const root = shadow(node);
        const predItem = root.querySelector<HTMLElement>(
            '.item[data-kind="predicate"][data-id="pred_0_age_gte"]'
        );
        expect(predItem?.querySelector('.state.allowed')).not.toBeNull();
    });

    it('emits CONSENT_EVENT with a result + receipt on approve', async () => {
        const node = mount();
        node.request = makeRequest();
        const root = shadow(node);
        // Allow age
        root.querySelector<HTMLButtonElement>('.item[data-key="age"] .toggle')?.click();

        const event = await new Promise<CustomEvent>((resolve) => {
            node.addEventListener(CONSENT_EVENT, (e) => resolve(e as CustomEvent), { once: true });
            const approve = shadow(node).querySelector<HTMLButtonElement>(
                'button[data-action="approve"]'
            );
            approve?.click();
        });

        const detail = event.detail as {
            result: { verdict: string; allowedClaims: string[]; allowedPredicateIds: string[] };
            receipt: { receiptId: string; verifierRef: string; rawClaimsStored: false };
        };
        expect(detail.result.verdict).toBe('CONSENTED');
        expect(detail.result.allowedClaims).toContain('age');
        expect(detail.result.allowedClaims).not.toContain('name');
        expect(detail.result.allowedPredicateIds).toContain('pred_0_age_gte');
        expect(detail.receipt.receiptId.startsWith('consent-')).toBe(true);
        expect(detail.receipt.verifierRef.startsWith('sha256:')).toBe(true);
        expect(detail.receipt.rawClaimsStored).toBe(false);
    });

    it('downgrades approve to WITHHELD verdict when nothing was allowed', async () => {
        const node = mount();
        // Predicate is allowed by default — make a request with only a requested-state predicate.
        node.request = makeRequest({
            claims: [{ key: 'age', policyState: 'requested' }],
            predicates: [
                {
                    id: 'pred_0_age_gte',
                    claim: 'age',
                    operation: 'gte',
                    value: 18,
                    policyState: 'requested',
                },
            ],
        });
        const event = await new Promise<CustomEvent>((resolve) => {
            node.addEventListener(CONSENT_EVENT, (e) => resolve(e as CustomEvent), { once: true });
            shadow(node)
                .querySelector<HTMLButtonElement>('button[data-action="approve"]')
                ?.click();
        });
        const detail = event.detail as { result: { verdict: string } };
        expect(detail.result.verdict).toBe('WITHHELD');
    });

    it('emits CONSENT_CANCEL_EVENT on cancel with all items withheld', async () => {
        const node = mount();
        node.request = makeRequest();
        const event = await new Promise<CustomEvent>((resolve) => {
            node.addEventListener(
                CONSENT_CANCEL_EVENT,
                (e) => resolve(e as CustomEvent),
                { once: true }
            );
            shadow(node)
                .querySelector<HTMLButtonElement>('button[data-action="cancel"]')
                ?.click();
        });
        const detail = event.detail as {
            result: {
                verdict: string;
                allowedClaims: string[];
                withheldClaims: string[];
                withheldPredicateIds: string[];
            };
        };
        expect(detail.result.verdict).toBe('CANCELLED');
        expect(detail.result.allowedClaims).toEqual([]);
        expect(detail.result.withheldClaims).toEqual(['age', 'name']);
        expect(detail.result.withheldPredicateIds).toEqual(['pred_0_age_gte']);
    });

    it('renders an error and refuses to render items when request is malformed', () => {
        const node = mount();
        // @ts-expect-error testing invalid payload
        node.request = { requestId: '', verifier: {}, claims: [], predicates: [] };
        const root = shadow(node);
        expect(root.querySelector('.error')).not.toBeNull();
        expect(root.querySelectorAll('.item').length).toBe(0);
    });

    it('renders text content via textContent so injected HTML in fields does not become DOM', () => {
        const node = mount();
        const xss = '<img src=x onerror="window.__pwned=1">';
        node.request = makeRequest({
            verifier: { id: 'did:x', displayName: xss },
            purpose: xss,
            claims: [{ key: xss, policyState: 'requested' }],
            predicates: [],
        });
        const root = shadow(node);
        // The script content was rendered as text, not as an <img>.
        expect(root.querySelector('img')).toBeNull();
        expect((root.textContent ?? '').includes(xss)).toBe(true);
        // Property never set.
        expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    });

    it('supports German strings via lang="de"', () => {
        const node = document.createElement(CONSENT_ELEMENT_TAG) as ConsentElement;
        node.setAttribute('lang', 'de');
        document.body.appendChild(node);
        node.request = makeRequest();
        const text = shadow(node).textContent ?? '';
        expect(text).toContain('Zustimmung erforderlich');
    });
});
