import type { Request } from 'express';

export function getRequesterId(req: Request): string {
    const trustProxy = Boolean(req.app.get('trust proxy'));
    const internalGateway = req.header('x-internal-gateway') === '1';
    const allowExplicit = trustProxy && internalGateway;

    if (allowExplicit) {
        const explicit = req.header('x-mitch-requester-id') || req.header('x-requester-id');
        if (explicit) return `hdr:${explicit}`;
    }

    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    return `ip:${ip}`;
}
