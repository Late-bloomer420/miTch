/**
 * <mitch-consent> — embeddable, framework-agnostic consent surface.
 *
 * Design rules:
 *   - Shadow DOM (open) for style isolation. Page DOM is untouched.
 *   - Every rendered string goes through textContent (see render.ts). No innerHTML.
 *   - Fail-closed: raw claims default to "withheld"; only an explicit per-item opt-in
 *     produces "allowed". Policy-denied items are non-toggleable.
 *   - Zero network, zero persistence by default. The host decides where the result goes.
 *   - All logic is local; no eval, no inline scripts, no remote resources.
 */

import { el, clear } from './render';
import { mergeTheme, themeToCssVars } from './theme';
import { DEFAULT_STRINGS_EN, stringsForLang } from './i18n';
import { buildConsentReceipt } from './receipt';
import type {
    ClaimItem,
    ConsentReceipt,
    ConsentRequest,
    ConsentResult,
    ConsentStrings,
    ConsentTheme,
    PredicateItem,
} from './types';

export const CONSENT_ELEMENT_TAG = 'mitch-consent';
export const CONSENT_EVENT = 'mitch-consent';
export const CONSENT_CANCEL_EVENT = 'mitch-consent-cancel';

const BASE_CSS = `
:host { display: block; box-sizing: border-box; color: var(--mc-text); font-family: var(--mc-font); }
.wrap { background: var(--mc-bg); border: 1px solid var(--mc-border); border-radius: var(--mc-radius); padding: 18px; max-width: 520px; }
.title { font-size: 16px; font-weight: 700; margin: 0 0 4px 0; color: var(--mc-text); }
.subtitle { font-size: 12px; color: var(--mc-muted); margin: 0 0 14px 0; }
.section-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--mc-muted); margin: 14px 0 6px 0; }
.empty { font-size: 12px; color: var(--mc-muted); font-style: italic; padding: 4px 0; }
.item { display: flex; align-items: center; justify-content: space-between; gap: 12px; background: var(--mc-surface); border: 1px solid var(--mc-border); border-radius: 8px; padding: 10px 12px; margin-bottom: 6px; }
.item .key { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--mc-text); }
.item .preview { font-size: 11px; color: var(--mc-muted); margin-left: 4px; }
.item .right { display: flex; align-items: center; gap: 10px; }
.state { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--mc-border); }
.state.requested { color: var(--mc-withhold); border-color: var(--mc-withhold); }
.state.allowed { color: var(--mc-allow); border-color: var(--mc-allow); }
.state.withheld { color: var(--mc-muted); border-color: var(--mc-border); }
.state.denied { color: var(--mc-deny); border-color: var(--mc-deny); }
.item[data-denied="true"] { opacity: 0.55; }
.item[data-denied="true"] .key { text-decoration: line-through; }
.toggle { appearance: none; width: 36px; height: 20px; border-radius: 10px; background: var(--mc-border); position: relative; cursor: pointer; border: none; padding: 0; transition: background 0.12s ease; }
.toggle::after { content: ''; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; background: var(--mc-text); border-radius: 50%; transition: left 0.12s ease; }
.toggle[aria-pressed="true"] { background: var(--mc-allow); }
.toggle[aria-pressed="true"]::after { left: 18px; }
.toggle:disabled { cursor: not-allowed; opacity: 0.5; }
.hint { font-size: 11px; color: var(--mc-muted); margin-top: 10px; }
.actions { display: flex; gap: 8px; margin-top: 14px; }
.btn { flex: 1; font-family: var(--mc-font); font-size: 13px; font-weight: 600; padding: 10px 12px; border-radius: 8px; cursor: pointer; border: 1px solid var(--mc-border); background: var(--mc-surface); color: var(--mc-text); }
.btn.primary { background: var(--mc-accent); border-color: var(--mc-accent); color: var(--mc-bg); }
.btn:focus-visible { outline: 2px solid var(--mc-accent); outline-offset: 2px; }
.error { color: var(--mc-deny); font-size: 12px; padding: 8px 0; }
`;

type ItemState = 'requested' | 'allowed' | 'withheld' | 'denied';

function initialClaimState(c: ClaimItem): ItemState {
    if (c.policyState === 'denied') return 'denied';
    if (c.policyState === 'allowed') return 'allowed';
    return 'withheld';
}

function initialPredicateState(p: PredicateItem): ItemState {
    if (p.policyState === 'denied') return 'denied';
    if (p.policyState === 'allowed') return 'allowed';
    return 'withheld';
}

function isValidRequest(req: unknown): req is ConsentRequest {
    if (!req || typeof req !== 'object') return false;
    const r = req as Record<string, unknown>;
    if (typeof r.requestId !== 'string' || r.requestId.length === 0) return false;
    if (typeof r.purpose !== 'string') return false;
    const v = r.verifier as Record<string, unknown> | undefined;
    if (!v || typeof v.id !== 'string' || v.id.length === 0) return false;
    if (!Array.isArray(r.claims)) return false;
    if (!Array.isArray(r.predicates)) return false;
    return true;
}

export class ConsentElement extends HTMLElement {
    private root: ShadowRoot;
    private _request: ConsentRequest | null = null;
    private _theme: Required<ConsentTheme> = mergeTheme(undefined);
    private _strings: ConsentStrings = DEFAULT_STRINGS_EN;
    private claimStates = new Map<string, ItemState>();
    private predicateStates = new Map<string, ItemState>();

    static get observedAttributes(): string[] {
        return ['request', 'lang'];
    }

    constructor() {
        super();
        this.root = this.attachShadow({ mode: 'open' });
    }

    connectedCallback(): void {
        this.applyLangFromAttr();
        this.applyRequestFromAttr();
        this.render();
    }

    attributeChangedCallback(name: string, _old: string | null, _next: string | null): void {
        if (name === 'lang') {
            this.applyLangFromAttr();
            this.render();
        } else if (name === 'request') {
            this.applyRequestFromAttr();
            this.render();
        }
    }

    /** Property setter — preferred over the JSON attribute for non-trivial requests. */
    set request(value: ConsentRequest | null) {
        if (value === null) {
            this._request = null;
            this.claimStates.clear();
            this.predicateStates.clear();
            this.render();
            return;
        }
        if (!isValidRequest(value)) {
            this._request = null;
            this.renderError('Invalid consent request: missing required fields.');
            return;
        }
        this._request = value;
        this.initStates();
        this.render();
    }

    get request(): ConsentRequest | null {
        return this._request;
    }

    set theme(value: ConsentTheme | null | undefined) {
        this._theme = mergeTheme(value);
        this.render();
    }

    get theme(): Required<ConsentTheme> {
        return this._theme;
    }

    set strings(value: Partial<ConsentStrings> | null | undefined) {
        if (!value) {
            this._strings = stringsForLang(this.getAttribute('lang'));
        } else {
            this._strings = { ...this._strings, ...value };
        }
        this.render();
    }

    get strings(): ConsentStrings {
        return this._strings;
    }

    private applyLangFromAttr(): void {
        this._strings = stringsForLang(this.getAttribute('lang'));
    }

    private applyRequestFromAttr(): void {
        const raw = this.getAttribute('request');
        if (!raw) return;
        try {
            const parsed = JSON.parse(raw) as unknown;
            if (!isValidRequest(parsed)) {
                this._request = null;
                this.renderError('Invalid consent request: missing required fields.');
                return;
            }
            this._request = parsed;
            this.initStates();
        } catch {
            this._request = null;
            this.renderError('Invalid consent request: malformed JSON.');
        }
    }

    private initStates(): void {
        this.claimStates.clear();
        this.predicateStates.clear();
        if (!this._request) return;
        for (const c of this._request.claims) this.claimStates.set(c.key, initialClaimState(c));
        for (const p of this._request.predicates)
            this.predicateStates.set(p.id, initialPredicateState(p));
    }

    private renderError(message: string): void {
        clear(this.root);
        const style = document.createElement('style');
        style.textContent = BASE_CSS;
        this.root.appendChild(style);
        const wrap = el(document, 'div', {
            class: 'wrap',
            attrs: { style: themeToCssVars(this._theme) },
        });
        wrap.appendChild(el(document, 'div', { class: 'error', text: message, role: 'alert' }));
        this.root.appendChild(wrap);
    }

    private render(): void {
        clear(this.root);

        const style = document.createElement('style');
        style.textContent = BASE_CSS;
        this.root.appendChild(style);

        const wrap = el(document, 'div', {
            class: 'wrap',
            role: 'group',
            attrs: { style: themeToCssVars(this._theme) },
        });

        if (!this._request) {
            wrap.appendChild(
                el(document, 'div', {
                    class: 'empty',
                    text: 'No consent request loaded.',
                })
            );
            this.root.appendChild(wrap);
            return;
        }

        const req = this._request;
        const s = this._strings;

        wrap.appendChild(el(document, 'h2', { class: 'title', text: s.title }));
        const subtitle = `${req.verifier.displayName ?? req.verifier.id} ${s.purposePrefix} ${req.purpose}`;
        wrap.appendChild(el(document, 'p', { class: 'subtitle', text: subtitle }));

        // Claims section
        wrap.appendChild(el(document, 'div', { class: 'section-title', text: s.sectionClaims }));
        if (req.claims.length === 0) {
            wrap.appendChild(el(document, 'div', { class: 'empty', text: s.emptyClaims }));
        } else {
            for (const c of req.claims) wrap.appendChild(this.renderClaim(c));
        }

        // Predicates section
        wrap.appendChild(
            el(document, 'div', { class: 'section-title', text: s.sectionPredicates })
        );
        if (req.predicates.length === 0) {
            wrap.appendChild(el(document, 'div', { class: 'empty', text: s.emptyPredicates }));
        } else {
            for (const p of req.predicates) wrap.appendChild(this.renderPredicate(p));
        }

        wrap.appendChild(el(document, 'div', { class: 'hint', text: s.failClosedHint }));

        // Actions
        const actions = el(document, 'div', { class: 'actions' });
        const approve = el(document, 'button', {
            class: 'btn primary',
            text: s.btnApprove,
            attrs: { type: 'button' },
            dataset: { action: 'approve' },
        });
        approve.addEventListener('click', () => this.emitApprove());
        const cancel = el(document, 'button', {
            class: 'btn',
            text: s.btnCancel,
            attrs: { type: 'button' },
            dataset: { action: 'cancel' },
        });
        cancel.addEventListener('click', () => this.emitCancel());
        actions.appendChild(approve);
        actions.appendChild(cancel);
        wrap.appendChild(actions);

        this.root.appendChild(wrap);
    }

    private renderClaim(c: ClaimItem): HTMLElement {
        const s = this._strings;
        const state = this.claimStates.get(c.key) ?? initialClaimState(c);
        const denied = c.policyState === 'denied';

        const item = el(document, 'div', {
            class: 'item',
            dataset: { kind: 'claim', key: c.key, denied: String(denied) },
        });

        const left = el(document, 'div', {});
        left.appendChild(el(document, 'span', { class: 'key', text: c.label ?? c.key }));
        if (c.preview && !denied) {
            left.appendChild(el(document, 'span', { class: 'preview', text: `· ${c.preview}` }));
        }

        const right = el(document, 'div', { class: 'right' });
        right.appendChild(this.renderStateBadge(state, denied ? s.deniedByPolicy : undefined));

        const toggle = el(document, 'button', {
            class: 'toggle',
            attrs: {
                type: 'button',
                'aria-pressed': state === 'allowed' ? 'true' : 'false',
                'aria-label': c.label ?? c.key,
            },
        });
        if (denied) toggle.setAttribute('disabled', '');
        toggle.addEventListener('click', () => {
            if (denied) return;
            const current = this.claimStates.get(c.key);
            const next: ItemState = current === 'allowed' ? 'withheld' : 'allowed';
            this.claimStates.set(c.key, next);
            this.render();
        });
        right.appendChild(toggle);

        item.appendChild(left);
        item.appendChild(right);
        return item;
    }

    private renderPredicate(p: PredicateItem): HTMLElement {
        const s = this._strings;
        const state = this.predicateStates.get(p.id) ?? initialPredicateState(p);
        const denied = p.policyState === 'denied';

        const item = el(document, 'div', {
            class: 'item',
            dataset: { kind: 'predicate', id: p.id, denied: String(denied) },
        });

        const left = el(document, 'div', {});
        const text = `${p.claim} ${p.operation} ${formatValue(p.value)}`;
        left.appendChild(el(document, 'span', { class: 'key', text }));

        const right = el(document, 'div', { class: 'right' });
        right.appendChild(this.renderStateBadge(state, denied ? s.deniedByPolicy : undefined));

        const toggle = el(document, 'button', {
            class: 'toggle',
            attrs: {
                type: 'button',
                'aria-pressed': state === 'allowed' ? 'true' : 'false',
                'aria-label': text,
            },
        });
        if (denied) toggle.setAttribute('disabled', '');
        toggle.addEventListener('click', () => {
            if (denied) return;
            const current = this.predicateStates.get(p.id);
            const next: ItemState = current === 'allowed' ? 'withheld' : 'allowed';
            this.predicateStates.set(p.id, next);
            this.render();
        });
        right.appendChild(toggle);

        item.appendChild(left);
        item.appendChild(right);
        return item;
    }

    private renderStateBadge(state: ItemState, deniedLabel?: string): HTMLElement {
        const s = this._strings;
        const cls = state;
        const label =
            state === 'denied'
                ? (deniedLabel ?? s.stateDenied)
                : state === 'allowed'
                  ? s.stateAllowed
                  : state === 'withheld'
                    ? s.stateWithheld
                    : s.stateRequested;
        return el(document, 'span', { class: `state ${cls}`, text: label });
    }

    private collectResult(verdict: 'CONSENTED' | 'WITHHELD' | 'CANCELLED'): ConsentResult {
        const req = this._request;
        if (!req) {
            return {
                requestId: '',
                verdict,
                allowedClaims: [],
                allowedPredicateIds: [],
                withheldClaims: [],
                withheldPredicateIds: [],
                timestamp: new Date().toISOString(),
            };
        }
        const allowedClaims: string[] = [];
        const withheldClaims: string[] = [];
        for (const c of req.claims) {
            const state = this.claimStates.get(c.key) ?? initialClaimState(c);
            if (state === 'allowed') allowedClaims.push(c.key);
            else withheldClaims.push(c.key);
        }
        const allowedPredicateIds: string[] = [];
        const withheldPredicateIds: string[] = [];
        for (const p of req.predicates) {
            const state = this.predicateStates.get(p.id) ?? initialPredicateState(p);
            if (state === 'allowed') allowedPredicateIds.push(p.id);
            else withheldPredicateIds.push(p.id);
        }
        return {
            requestId: req.requestId,
            verdict,
            allowedClaims,
            allowedPredicateIds,
            withheldClaims,
            withheldPredicateIds,
            timestamp: new Date().toISOString(),
        };
    }

    private async emitApprove(): Promise<void> {
        if (!this._request) return;
        const provisional = this.collectResult('CONSENTED');
        const verdict: 'CONSENTED' | 'WITHHELD' =
            provisional.allowedClaims.length === 0 && provisional.allowedPredicateIds.length === 0
                ? 'WITHHELD'
                : 'CONSENTED';
        const result: ConsentResult = { ...provisional, verdict };
        let receipt: ConsentReceipt | null = null;
        try {
            receipt = await buildConsentReceipt(this._request, result);
        } catch (e) {
            this.renderError(
                `Receipt could not be built: ${e instanceof Error ? e.message : String(e)}`
            );
            return;
        }
        this.dispatchEvent(
            new CustomEvent(CONSENT_EVENT, {
                detail: { result, receipt },
                bubbles: true,
                composed: true,
            })
        );
    }

    private emitCancel(): void {
        const result = this.collectResult('CANCELLED');
        result.allowedClaims = [];
        result.allowedPredicateIds = [];
        if (this._request) {
            result.withheldClaims = this._request.claims.map((c) => c.key);
            result.withheldPredicateIds = this._request.predicates.map((p) => p.id);
        }
        this.dispatchEvent(
            new CustomEvent(CONSENT_CANCEL_EVENT, {
                detail: { result },
                bubbles: true,
                composed: true,
            })
        );
    }
}

function formatValue(v: unknown): string {
    if (v === null) return 'null';
    if (typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    try {
        return JSON.stringify(v);
    } catch {
        return '[value]';
    }
}

let defined = false;
/**
 * Register the <mitch-consent> custom element. Safe to call multiple times.
 * Returns true if newly registered, false if already registered.
 */
export function defineConsentElement(): boolean {
    if (defined) return false;
    if (typeof customElements === 'undefined') return false;
    if (customElements.get(CONSENT_ELEMENT_TAG)) {
        defined = true;
        return false;
    }
    customElements.define(CONSENT_ELEMENT_TAG, ConsentElement);
    defined = true;
    return true;
}
