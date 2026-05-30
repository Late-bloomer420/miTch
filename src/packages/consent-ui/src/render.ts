/**
 * Safe DOM construction helpers.
 *
 * Rules enforced here:
 *   - Never assign to innerHTML, outerHTML, or insertAdjacentHTML.
 *   - String content goes through textContent only.
 *   - Attribute values are set via setAttribute on element references we created.
 *   - No event handler attributes (onclick=...). All listeners are added via addEventListener.
 *
 * Keep this file free of any logic that interprets request strings — it only renders.
 */

export interface ElProps {
    class?: string;
    text?: string;
    title?: string;
    role?: string;
    ariaLabel?: string;
    dataset?: Record<string, string>;
    attrs?: Record<string, string>;
}

export function el<K extends keyof HTMLElementTagNameMap>(
    doc: Document,
    tag: K,
    props: ElProps = {},
    children: readonly (Node | string)[] = []
): HTMLElementTagNameMap[K] {
    const node = doc.createElement(tag);
    if (props.class !== undefined) node.className = props.class;
    if (props.text !== undefined) node.textContent = props.text;
    if (props.title !== undefined) node.title = props.title;
    if (props.role !== undefined) node.setAttribute('role', props.role);
    if (props.ariaLabel !== undefined) node.setAttribute('aria-label', props.ariaLabel);
    if (props.dataset) {
        for (const [k, v] of Object.entries(props.dataset)) {
            node.dataset[k] = v;
        }
    }
    if (props.attrs) {
        for (const [k, v] of Object.entries(props.attrs)) {
            node.setAttribute(k, v);
        }
    }
    for (const child of children) {
        if (typeof child === 'string') {
            node.appendChild(doc.createTextNode(child));
        } else {
            node.appendChild(child);
        }
    }
    return node;
}

export function clear(node: Node): void {
    while (node.firstChild) node.removeChild(node.firstChild);
}
