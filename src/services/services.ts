import { authCodes, refreshTokens, families } from '../infrastructure/stores/stores.js'
import { OAuthError } from '../domain/errors.js'
import { computeAtHash, randomId, sha256 } from '../infrastructure/crypto/utils.js'
import { AccessTokenPayload, signJwt } from '../infrastructure/crypto/jwt.js'
import { verifyJwt, validateAccessTokenClaims } from '../infrastructure/crypto/jwt.js'
import { generateKeyPairSync } from 'crypto'
import type { Client, AuthorizationCode, RefreshToken } from '../domain/models.js'


const keys = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
})

export const privateKey = keys.privateKey
export const publicKey = keys.publicKey
export const kid = randomId()

interface CreateAuthorizationCodeInput extends Omit<AuthorizationCode, 'code'> {}
export function createAuthorizationCode(data: CreateAuthorizationCodeInput): string {
  const code = randomId()
  authCodes.set(code, { ...data, code })
  return code
}

interface AuthorizationCodeGrantParams {
  code: string
  redirect_uri: string
  code_verifier: string
}

export class TokenService {
  constructor(public readonly issuer: string) {}
   exchangeCode(
  client: Client,
  params: AuthorizationCodeGrantParams
): { accessToken: string; refreshToken?: string | undefined; idToken?: string | undefined } {
  const stored = authCodes.get(params.code)
  const now = Math.floor(Date.now()/1000)

  if (!stored ||
      stored.clientId !== client.id ||
      stored.redirectUri !== params.redirect_uri ||
      stored.expiresAt < now ||
      sha256(params.code_verifier) !== stored.codeChallenge) {
    throw new OAuthError('invalid_grant')
  }

  authCodes.delete(params.code)

  const accessToken = signJwt({
    iss: this.issuer,
    sub: stored.userId,
    aud: 'resource_server',
    iat: now,
    exp: now + 3600,
    scope: stored.scope.join(' ')
  }, privateKey, kid)

  let refreshToken

  if (stored.scope.includes('offline_access')) {
    const id = randomId()

    refreshTokens.set(id, {
      id,
      clientId: client.id,
      userId: stored.userId,
      scope: stored.scope,
      expiresAt: now + (client.refreshTokenLifetimeSeconds ?? 2592000),
      rootId: id,
      used: false,
      revoked: false
    })

    families.set(id, new Set([id]))
    refreshToken = id
  } 

  let idToken;
  if (stored.scope.includes('openid')) {
      idToken = signJwt({
        iss: this.issuer,
        sub: stored.userId,
        aud: client.id,
        iat: now,
        exp: now + 3600,
        auth_time: stored.authTime,
        at_hash: computeAtHash(accessToken),
        ...(stored.nonce ? { nonce: stored.nonce } : {})
      }, privateKey, kid)
  }
  

  return { accessToken, refreshToken, idToken }
}

  exchangeRefresh(
  client: Client,
  tokenId: string
): { accessToken: string; refreshToken: string } {
  const stored = refreshTokens.get(tokenId)
  const now = Math.floor(Date.now()/1000)

  if (!stored || stored.clientId !== client.id ||
      stored.expiresAt < now || stored.revoked) {
    throw new OAuthError('invalid_grant')
  }

  if (stored.used) {
    const fam = families.get(stored.rootId)
    fam?.forEach((id: string) => {
      const t = refreshTokens.get(id)
      if (t) {
        const updated: RefreshToken = { ...t, revoked: true }
        refreshTokens.set(id, updated)
      }
    })
    throw new OAuthError('invalid_grant')
  }

  const updatedStored: RefreshToken = { ...stored, used: true }
  refreshTokens.set(stored.id, updatedStored)

  const newId = randomId()

  const newRefreshToken: RefreshToken = {
    id: newId,
    clientId: stored.clientId,
    userId: stored.userId,
    scope: stored.scope,
    expiresAt: now + (client.refreshTokenLifetimeSeconds ?? 2592000),
    rootId: stored.rootId,
    parentId: stored.id,
    used: false,
    revoked: false
  }

  refreshTokens.set(newId, newRefreshToken)

  families.get(stored.rootId)?.add(newId)

  const accessToken = signJwt({
    iss: this.issuer,
    sub: stored.userId,
    aud: 'resource_server',
    iat: now,
    exp: now + 3600,
    scope: stored.scope.join(' ')
  }, privateKey, kid)

  return { accessToken, refreshToken: newId }
}

  exchangeToken(
  client: Client,
  subjectToken: string,
  actor?: { sub: string, [claim: string]: unknown},
  requestedScope?: string[]
): { accessToken: string; refreshToken: string } {

  if (!client.allowTokenExchange) {
    throw new OAuthError('unauthorized_client')
  }

  const verified = verifyJwt<AccessTokenPayload>(subjectToken, publicKey)
  const payload = validateAccessTokenClaims(verified, {
    expectedIssuer: this.issuer,
    rejectDelegated: true
  })

  const now = Math.floor(Date.now() / 1000)

  const originalScopes = payload.scope
    ? payload.scope.split(' ')
    : []

  const finalScopes = requestedScope && requestedScope.length > 0
    ? requestedScope.filter(s => originalScopes.includes(s))
    : originalScopes

  if (finalScopes.length === 0) {
    throw new OAuthError('invalid_scope')
  }

  // enforce strict subset (no escalation)
  const isSubset = finalScopes.every(s => originalScopes.includes(s))
  if (!isSubset) {
    throw new OAuthError('invalid_scope')
  }

  const delegationTTL = 900 // 15 minutes

  const newExp = Math.min(
    payload.exp,
    now + delegationTTL
  )

  const jti = randomId()

  const accessToken = signJwt({
    iss: this.issuer,
    sub: payload.sub,
    aud: payload.aud,
    iat: now,
    exp: newExp,
    scope: finalScopes.join(' '),
    act: actor,
    delegated_from: payload.jti,
    jti
  }, privateKey, kid)

  const refreshId = randomId()

  const newRefreshToken: RefreshToken = {
    id: refreshId,
    clientId: client.id,
    userId: payload.sub,
    scope: finalScopes,
    expiresAt: Math.min(
      payload.exp,
      now + (client.refreshTokenLifetimeSeconds ?? 2592000)
    ),
    rootId: refreshId,
    used: false,
    revoked: false,
    act: actor,
    delegatedFrom: payload.jti
  }

  refreshTokens.set(refreshId, newRefreshToken)
  families.set(refreshId, new Set([refreshId]))

  return { accessToken, refreshToken: refreshId }
}

}
