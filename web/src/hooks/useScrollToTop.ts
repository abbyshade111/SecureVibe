import { useEffect } from 'react';

/**
 * Puts a new step of a multi-step page back at the top.
 *
 * The browser keeps the scroll position when only part of the page changes, so after a long question the next one
 * would open half-way down. Every time `key` changes, the window goes back to the top instantly (a smooth scroll
 * on a long page is disorienting, and instant is what a new page would do).
 */
export function useScrollToTop(key: unknown): void {
  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
    } catch {
      // very old browsers: the options form is not supported
      window.scrollTo(0, 0);
    }
  }, [key]);
}
