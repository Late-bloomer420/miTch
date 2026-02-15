import { createHash } from 'node:crypto';
import { Hex32, InclusionProof } from '@mitch/shared-types';
import { MerkleBuildResult } from './types.js';

/**
 * Computes SHA-256 of input buffer(s).
 */
function sha256(data: Buffer): Buffer {
    return createHash('sha256').update(data).digest();
}

/**
 * Concatenates and hashes two nodes.
 * Enforces canonical ordering (sorts a/b) to prevent malleability.
 * Hash(min(a,b) + max(a,b))
 */
function hashPair(a: Buffer, b: Buffer): Buffer {
    const sorted = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
    return sha256(Buffer.concat(sorted));
}

export function buildMerkleTree(decisionHashes: Hex32[]): MerkleBuildResult {
    if (decisionHashes.length === 0) {
        throw new Error("Cannot build Merkle Tree from empty batch");
    }

    // 1. Deduplicate & Sort (Canonical Ordering)
    const uniqueSorted = Array.from(new Set(decisionHashes)).sort();

    // 2. Convert to Buffers
    const leaves: Buffer[] = uniqueSorted.map(h => Buffer.from(h, 'hex'));

    // 3. Keep ordered hex list for reference (needed for proof index)
    const orderedDecisionHashes = uniqueSorted;

    const levels: Buffer[][] = [leaves];

    // 4. Build up to Root
    let currentLevel = leaves;
    while (currentLevel.length > 1) {
        const nextLevel: Buffer[] = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            // If odd number of nodes, duplicate the last one
            const right = (i + 1 < currentLevel.length)
                ? currentLevel[i + 1]
                : left;

            nextLevel.push(hashPair(left, right));
        }
        levels.push(nextLevel);
        currentLevel = nextLevel;
    }

    const rootBuffer = currentLevel[0];

    return {
        root: rootBuffer.toString('hex') as Hex32,
        orderedDecisionHashes,
        leafHashes: leaves,
        levels
    };
}

/**
 * Generates a proof for a specific hash within the tree.
 */
export function getInclusionProof(
    tree: MerkleBuildResult,
    targetHash: Hex32
): InclusionProof {
    // Find index in the sorted leaves
    const leafIndex = tree.orderedDecisionHashes.indexOf(targetHash);
    if (leafIndex === -1) {
        throw new Error("Target hash not found in this tree");
    }

    const proof: string[] = [];
    let currentIndex = leafIndex;

    // Traverse levels (excluding the root level)
    for (let i = 0; i < tree.levels.length - 1; i++) {
        const level = tree.levels[i];
        const isRightNode = currentIndex % 2 === 1;

        // Determine sibling index
        const pairIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

        // If pairIndex is out of bounds (odd number of nodes), duplicate self logic applies
        const pairNode = (pairIndex < level.length)
            ? level[pairIndex]
            : level[currentIndex];

        proof.push(pairNode.toString('hex'));

        // Move up to next level
        currentIndex = Math.floor(currentIndex / 2);
    }

    return {
        root: tree.root,
        target: targetHash,
        siblings: proof
    };
}
