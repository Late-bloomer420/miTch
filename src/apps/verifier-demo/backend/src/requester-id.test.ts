import { describe, it, expect } from 'vitest';
import { getRequesterId } from './requester-id';

function mockReq(opts: {
    trustProxy: boolean;
    headers?: Record<string, string | undefined>;
    ip?: string;
    remoteAddress?: string;
}) {
    const headers = opts.headers ?? {};
    return {
        app: { get: (key: string) => (key === 'trust proxy' ? opts.trustProxy : undefined) },
        header: (name: string) => headers[name.toLowerCase()],
        ip: opts.ip,
        socket: { remoteAddress: opts.remoteAddress }
    } as any;
}

describe('getRequesterId', () => {
    it('ignores explicit requester id when trust proxy is off', () => {
        const req = mockReq({
            trustProxy: false,
            headers: { 'x-mitch-requester-id': 'abc', 'x-internal-gateway': '1' },
            ip: '10.0.0.1'
        });
        expect(getRequesterId(req)).toBe('ip:10.0.0.1');
    });

    it('ignores explicit requester id when internal gateway flag is missing', () => {
        const req = mockReq({
            trustProxy: true,
            headers: { 'x-mitch-requester-id': 'abc' },
            ip: '10.0.0.2'
        });
        expect(getRequesterId(req)).toBe('ip:10.0.0.2');
    });

    it('honors explicit requester id only when trust proxy is on AND internal gateway is set', () => {
        const req = mockReq({
            trustProxy: true,
            headers: { 'x-mitch-requester-id': 'abc', 'x-internal-gateway': '1' },
            ip: '10.0.0.3'
        });
        expect(getRequesterId(req)).toBe('hdr:abc');
    });

    it('falls back to remoteAddress when req.ip is missing', () => {
        const req = mockReq({
            trustProxy: false,
            headers: {},
            ip: undefined,
            remoteAddress: '127.0.0.1'
        });
        expect(getRequesterId(req)).toBe('ip:127.0.0.1');
    });
});
