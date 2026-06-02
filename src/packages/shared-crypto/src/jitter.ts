/**
 * U-23: Timing Jitter Utility
 * 
 * Introduces random, cryptographically-sourced delays to network requests.
 * Prevents side-channel analysis of processing time or payload complexity.
 */

import { crypto } from './platform';

/**
 * Returns a promise that resolves after a random delay.
 * @param minMs Minimum delay in milliseconds (default 10)
 * @param maxMs Maximum delay in milliseconds (default 50)
 */
export async function applyJitter(minMs: number = 10, maxMs: number = 50): Promise<void> {
    const range = maxMs - minMs;
    const randomBuffer = new Uint32Array(1);
    crypto.getRandomValues(randomBuffer);
    
    // Normalize random value to the desired range
    const delay = minMs + (randomBuffer[0] % (range + 1));
    
    return new Promise(resolve => setTimeout(resolve, delay));
}
