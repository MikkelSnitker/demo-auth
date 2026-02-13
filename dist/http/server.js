import http from 'http';
import { OAuthError } from '../domain/errors.js';
import { createAuthorizationCode, exchangeCode, exchangeRefresh, issuer, publicKey, kid } from '../services/services.js';
import { clients } from '../infrastructure/stores/stores.js';
import { createPublicKey } from 'crypto';
export function startServer() {
    return http.createServer(async (req, res) => {
        try {
            const url = new URL(req.url ?? '', issuer);
            if (url.pathname === '/.well-known/jwks.json') {
                const keyObj = createPublicKey(publicKey);
                const jwk = keyObj.export({ format: 'jwk' });
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ keys: [{
                            kty: jwk.kty, n: jwk.n, e: jwk.e,
                            alg: 'RS256', use: 'sig', kid
                        }] }));
            }
            if (url.pathname === '/.well-known/openid-configuration') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({
                    issuer,
                    authorization_endpoint: issuer + '/authorize',
                    token_endpoint: issuer + '/token',
                    jwks_uri: issuer + '/.well-known/jwks.json',
                    response_types_supported: ['code'],
                    grant_types_supported: ['authorization_code', 'refresh_token'],
                    id_token_signing_alg_values_supported: ['RS256']
                }));
            }
            if (url.pathname === '/authorize') {
                const clientId = url.searchParams.get('client_id');
                const redirectUri = url.searchParams.get('redirect_uri');
                const challenge = url.searchParams.get('code_challenge');
                const method = url.searchParams.get('code_challenge_method');
                const scope = (url.searchParams.get('scope') ?? '').split(' ');
                const state = url.searchParams.get('state');
                if (!clientId || !redirectUri || !challenge || method !== 'S256') {
                    throw new OAuthError('invalid_request');
                }
                const client = clients.get(clientId);
                if (!client || !client.redirectUris.includes(redirectUri)) {
                    throw new OAuthError('invalid_request');
                }
                const code = createAuthorizationCode({
                    clientId,
                    userId: 'user1',
                    redirectUri,
                    scope,
                    codeChallenge: challenge,
                    expiresAt: Math.floor(Date.now() / 1000) + 300
                });
                const redirect = new URL(redirectUri);
                redirect.searchParams.set('code', code);
                if (state)
                    redirect.searchParams.set('state', state);
                res.writeHead(302, { Location: redirect.toString() });
                return res.end();
            }
            if (url.pathname === '/token' && req.method === 'POST') {
                let body = '';
                req.on('data', c => body += c);
                req.on('end', () => {
                    try {
                        const params = Object.fromEntries(new URLSearchParams(body));
                        const auth = req.headers['authorization'];
                        if (!auth?.startsWith('Basic '))
                            throw new OAuthError('invalid_client', 401);
                        const decoded = Buffer.from(auth.slice(6), 'base64').toString();
                        const [clientId, secret] = decoded.split(':');
                        const client = clients.get(clientId);
                        if (!client || secret !== client.secret)
                            throw new OAuthError('invalid_client', 401);
                        if (params.grant_type === 'authorization_code') {
                            const result = exchangeCode(client, params);
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({
                                access_token: result.accessToken,
                                refresh_token: result.refreshToken,
                                token_type: 'Bearer',
                                expires_in: 3600
                            }));
                        }
                        if (params.grant_type === 'refresh_token') {
                            const result = exchangeRefresh(client, params.refresh_token);
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({
                                access_token: result.accessToken,
                                refresh_token: result.refreshToken,
                                token_type: 'Bearer',
                                expires_in: 3600
                            }));
                        }
                        throw new OAuthError('unsupported_grant_type');
                    }
                    catch (err) {
                        handleError(err, res);
                    }
                });
                return;
            }
            res.writeHead(404);
            res.end();
        }
        catch (err) {
            handleError(err, res);
        }
    });
}
function handleError(err, res) {
    if (err instanceof OAuthError) {
        if (err.statusCode === 401) {
            res.setHeader('WWW-Authenticate', 'Basic realm="token"');
        }
        res.writeHead(err.statusCode, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.error }));
    }
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'server_error' }));
}
//# sourceMappingURL=server.js.map