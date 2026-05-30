/**
 * LandingPage — smoke tests for the default marketing view
 */

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';

import { LandingPage } from '../LandingPage';

describe('LandingPage', () => {
  it('renders the hero heading', () => {
    render(<LandingPage onLaunchDemo={() => {}} />);
    expect(screen.getByRole('heading', { name: /verify the fact\. forget the data\./i })).toBeTruthy();
  });

  it('invokes onLaunchDemo when the primary CTA is clicked', () => {
    const onLaunchDemo = vi.fn();
    render(<LandingPage onLaunchDemo={onLaunchDemo} />);
    fireEvent.click(screen.getByRole('button', { name: /run the live proof/i }));
    expect(onLaunchDemo).toHaveBeenCalledTimes(1);
  });
});
