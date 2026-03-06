/**
 * G-01 — Wallet PWA: DocumentService Tests
 */

import { describe, it, expect } from 'vitest';
import { DocumentService } from '../services/DocumentService';

// ─── helpers ────────────────────────────────────────────────────────────────

function makeFile(content: string, name = 'test.txt', type = 'text/plain'): File {
    return new File([content], name, { type });
}

// ─── DocumentService.hashFile ────────────────────────────────────────────────

describe('G-01 — DocumentService.hashFile', () => {
    it('returns a 64-char hex SHA-256 hash', async () => {
        const file = makeFile('hello world');
        const hash = await DocumentService.hashFile(file);
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[0-9a-f]+$/);
    });

    it('same content → same hash (deterministic)', async () => {
        const f1 = makeFile('deterministic-content');
        const f2 = makeFile('deterministic-content');
        const h1 = await DocumentService.hashFile(f1);
        const h2 = await DocumentService.hashFile(f2);
        expect(h1).toBe(h2);
    });

    it('different content → different hash', async () => {
        const h1 = await DocumentService.hashFile(makeFile('content-A'));
        const h2 = await DocumentService.hashFile(makeFile('content-B'));
        expect(h1).not.toBe(h2);
    });

    it('empty file hashes correctly (SHA-256 of empty = e3b0c44...)', async () => {
        const hash = await DocumentService.hashFile(makeFile(''));
        expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('binary content (non-text) hashes without error', async () => {
        const bytes = new Uint8Array([0x00, 0xff, 0xab, 0xcd]);
        const file = new File([bytes], 'binary.bin', { type: 'application/octet-stream' });
        const hash = await DocumentService.hashFile(file);
        expect(hash).toHaveLength(64);
    });
});

// ─── DocumentService.createProofOfExistence ──────────────────────────────────

describe('G-01 — DocumentService.createProofOfExistence', () => {
    it('returns correct structural shape', () => {
        const file = makeFile('test content', 'doc.txt', 'text/plain');
        const proof = DocumentService.createProofOfExistence('abc123', file, 'My Document');
        expect(proof.type).toBe('ProofOfExistence');
        expect(proof.hash).toBe('abc123');
        expect(proof.hashAlg).toBe('SHA-256');
        expect(proof.mediaType).toBe('text/plain');
        expect(proof.description).toBe('My Document');
        expect(proof.byteLength).toBe(12); // 'test content'.length
        expect(proof.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('uses application/octet-stream when file.type is empty', () => {
        const file = new File(['data'], 'notype');
        const proof = DocumentService.createProofOfExistence('hash-x', file, 'desc');
        expect(proof.mediaType).toBe('application/octet-stream');
    });

    it('byteLength reflects actual file size', () => {
        const content = 'A'.repeat(1024);
        const file = makeFile(content, 'big.txt', 'text/plain');
        const proof = DocumentService.createProofOfExistence('h', file, 'big');
        expect(proof.byteLength).toBe(1024);
    });

    it('createdAt is an ISO timestamp close to now', () => {
        const before = Date.now();
        const file = makeFile('x');
        const proof = DocumentService.createProofOfExistence('h', file, 'd');
        const after = Date.now();
        const ts = new Date(proof.createdAt).getTime();
        expect(ts).toBeGreaterThanOrEqual(before);
        expect(ts).toBeLessThanOrEqual(after + 5); // 5ms tolerance
    });

    it('round-trip: hash file then create proof', async () => {
        const file = makeFile('round-trip content', 'rt.txt', 'text/plain');
        const hash = await DocumentService.hashFile(file);
        const proof = DocumentService.createProofOfExistence(hash, file, 'Round Trip');
        expect(proof.hash).toBe(hash);
        expect(proof.hash).toHaveLength(64);
    });
});
