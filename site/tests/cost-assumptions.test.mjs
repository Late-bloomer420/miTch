import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

// Exercise the public generic-flow renderer, not a duplicate calculator.
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const start = html.indexOf('    const COSTS =');
const end = html.indexOf('    // ─── Revocation', start);
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
  const first = html.indexOf('<script>');
  const last = html.lastIndexOf('</script>');
  assert(first >= 0 && last > first);
  new vm.Script(html.slice(first + '<script>'.length, last));
});

test('every selectable scenario preserves unknown exposure and suppresses savings', () => {
  const elements = new Map();
  const context = { activeScenario: null, document: { getElementById(id) {
    if (!elements.has(id)) elements.set(id, { style: {}, innerHTML: '' });
    return elements.get(id);
  } } };
  vm.createContext(context);
  const from = html.indexOf('    const SCENARIOS =');
  const to = html.indexOf('    let activeScenario =', from);
  assert(from >= 0 && to > from);
  vm.runInContext(html.slice(from, to), context);
  vm.runInContext(html.slice(start, end), context);
  const keys = vm.runInContext('Object.keys(SCENARIOS)', context);
  assert(keys.length >= 5);
  for (const key of keys) {
    context.activeScenario = key;
    vm.runInContext("renderCosts('verification')", context);
    const summary = elements.get('cost-savings').innerHTML;
    assert(summary.includes('Total cost and savings: unknown'), key);
    assert(!/\d+%/.test(summary), key);
    assert(elements.get('cost-AskMI').innerHTML.includes('Unknown'), key);
    assert(elements.get('cost-AskMI-total').innerHTML.includes('unknown costs'), key);
  }
});

test('annual TCO excludes missing storage/risk from claims of total savings', () => {
  const elements = new Map();
  const context = { document: { getElementById(id) {
    if (!elements.has(id)) elements.set(id, { value: '100000', textContent: '', innerHTML: '' });
    return elements.get(id);
  } } };
  vm.createContext(context);
  const from = html.indexOf('    function updateTCO()');
  const to = html.indexOf('    const tcoSlider =', from);
  assert(from >= 0 && to > from);
  vm.runInContext(html.slice(from, to), context);
  vm.runInContext('updateTCO()', context);
  assert(elements.get('tco-savings').textContent.includes('Unknown'));
  assert(!/\d+%/.test(elements.get('tco-savings').textContent));
  assert(!/€\s*0/.test(elements.get('tco-savings').textContent));
});
