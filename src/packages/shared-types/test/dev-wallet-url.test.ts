import { describe, expect, it } from 'vitest';
import { askmiDevWalletUrl, askmiDevWalletUsesHttps } from '../src/askmi';

describe('askmiDevWalletUrl', () => {
  it('defaults to the HTTPS wallet dev origin', () => {
    expect(askmiDevWalletUsesHttps(undefined)).toBe(true);
    expect(askmiDevWalletUrl(undefined)).toBe('https://localhost:5174');
  });
  it('switches to HTTP only for ASKMI_DEV_HTTPS=0', () => {
    expect(askmiDevWalletUsesHttps('0')).toBe(false);
    expect(askmiDevWalletUrl('0')).toBe('http://localhost:5174');
  });
  it.each(['1', '', 'false', 'no'])('keeps HTTPS for ASKMI_DEV_HTTPS=%j', (value) => {
    expect(askmiDevWalletUrl(value)).toBe('https://localhost:5174');
  });
});
