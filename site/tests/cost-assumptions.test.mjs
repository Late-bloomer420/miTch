import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

// Exercise the public generic-flow renderer, not a duplicate calculator.
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const start = html.indexOf('    const COSTS =');
const end = html.indexOf('    function renderScenarioCosts(costs)', start);
assert(start >= 0 && end > start, 'public cost renderer must be available');

test('unknown deployment costs never become zero prices or savings claims', () => {
  const elements = new Map();
  const context = {
    activeScenario: null,
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { style: {}, innerHTML: '' });
        return elements.get(id);
      },
    },
  };
  vm.createContext(context);
  vm.runInContext(html.slice(start, end), context);

  for (const phase of ['issuance', 'verification']) {
    vm.runInContext(`renderCosts('${phase}')`, context);
    const rows = elements.get('cost-AskMI').innerHTML.split('</li>');
    for (const label of ['PII Storage', 'Data Breach Risk']) {
      const row = rows.find((value) => value.includes(`<span>${label}</span>`));
      assert(row?.includes('Unknown'), `${phase}: ${label} must be unknown`);
      assert(!row.includes('€0.000'), `${phase}: ${label} is not a zero cost`);
    }
    const summary = elements.get('cost-savings').innerHTML;
    assert(summary.includes('Total cost and savings: unknown'));
    assert(!/\d+%/.test(summary), 'incomplete input must not yield percentage savings');
    assert(!summary.includes('Users/Jahr'), 'no annual savings extrapolation');
    assert(!summary.includes('NaN'), 'known subtotal remains numeric');
    assert(elements.get('cost-AskMI-total').innerHTML.includes('unknown costs'));
  }
});

test('complete embedded script remains syntactically valid', () => {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
  assert(scripts.length > 0);
  for (const [, source] of scripts) new vm.Script(source);
});
