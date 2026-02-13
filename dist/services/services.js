import { authCodes, refreshTokens, families } from '../infrastructure/stores/stores.js';
import { OAuthError } from '../domain/errors.js';
import { randomId, sha256 } from '../infrastructure/crypto/utils.js';
import { signJwt } from '../infrastructure/crypto/jwt.js';
import { generateKeyPairSync } from 'crypto';
export const issuer = 'http://localhost:4000';
const keys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
export const privateKey = keys.privateKey;
export const publicKey = keys.publicKey;
export const kid = randomId();
export function createAuthorizationCode(data) {
    const code = randomId();
    authCodes.set(code, { ...data, code });
    return code;
}
export function exchangeCode(client, params) {
    const stored = authCodes.get(params.code);
    const now = Math.floor(Date.now() / 1000);
    if (!stored ||
        stored.clientId !== client.id ||
        stored.redirectUri !== params.redirect_uri ||
        stored.expiresAt < now ||
        sha256(params.code_verifier) !== stored.codeChallenge) {
        throw new OAuthError('invalid_grant');
    }
    authCodes.delete(params.code);
    const accessToken = signJwt({
        iss: issuer,
        sub: stored.userId,
        aud: 'resource_server',
        iat: now,
        exp: now + 3600,
        scope: stored.scope.join(' ')
    }, privateKey, kid);
    let refreshToken;
    if (stored.scope.includes('offline_access')) {
        const id = randomId();
        refreshTokens.set(id, {
            id,
            clientId: client.id,
            userId: stored.userId,
            scope: stored.scope,
            expiresAt: now + (client.refreshTokenLifetimeSeconds ?? 2592000),
            rootId: id,
            used: false,
            revoked: false
        });
        families.set(id, new Set([id]));
        refreshToken = id;
    }
    return { accessToken, refreshToken };
}
export function exchangeRefresh(client, tokenId) {
    const stored = refreshTokens.get(tokenId);
    const now = Math.floor(Date.now() / 1000);
    if (!stored || stored.clientId !== client.id ||
        stored.expiresAt < now || stored.revoked) {
        throw new OAuthError('invalid_grant');
    }
    if (stored.used) {
        const fam = families.get(stored.rootId);
        fam?.forEach(id => {
            const t = refreshTokens.get(id);
            if (t)
                t.revoked = true;
        });
        throw new OAuthError('invalid_grant');
    }
    stored.used = true;
    const newId = randomId();
    refreshTokens.set(newId, {
        id: newId,
        clientId: stored.clientId,
        userId: stored.userId,
        scope: stored.scope,
        expiresAt: now + (client.refreshTokenLifetimeSeconds ?? 2592000),
        rootId: stored.rootId,
        parentId: stored.id,
        used: false,
        revoked: false
    });
    families.get(stored.rootId)?.add(newId);
    const accessToken = signJwt({
        iss: issuer,
        sub: stored.userId,
        aud: 'resource_server',
        iat: now,
        exp: now + 3600,
        scope: stored.scope.join(' ')
    }, privateKey, kid);
    return { accessToken, refreshToken: newId };
}
//# sourceMappingURL=services.js.map