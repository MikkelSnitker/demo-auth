import { createSign, createVerify } from 'crypto'
import { base64url } from './utils.js'

export interface JwtHeader {
  alg: string
  typ: string
  kid: string
}

export interface AccessTokenPayload {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  scope?: string
  act?: { sub: string }
  jti?: string
  [claim: string]: unknown
}

export interface VerifiedJwt<TPayload extends Record<string, unknown>> {
  header: JwtHeader
  payload: TPayload
}

export function signJwt<T extends Record<string, unknown>>(payload: T, privateKey: string, kid: string) {
  const header = { alg: 'RS256', typ: 'JWT', kid }
  const encodedHeader = base64url(Buffer.from(JSON.stringify(header)))
  const encodedPayload = base64url(Buffer.from(JSON.stringify(payload)))
  const data = `${encodedHeader}.${encodedPayload}`
  const signer = createSign('RSA-SHA256')
  signer.update(data)
  signer.end()
  const sig = signer.sign(privateKey)
  return `${data}.${base64url(sig)}`
}

export function verifyJwt<TPayload extends Record<string, unknown>>(
  token: string,
  publicKey: string,
  expectedAlg: 'RS256' = 'RS256'
): VerifiedJwt<TPayload> {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('invalid_token')
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  const header = JSON.parse(
    Buffer.from(encodedHeader, 'base64url').toString('utf8')
  ) as JwtHeader

  if (header.alg !== expectedAlg) {
    throw new Error('invalid_token')
  }

  const verifier = createVerify('RSA-SHA256')
  verifier.update(`${encodedHeader}.${encodedPayload}`)
  verifier.end()

  const isValid = verifier.verify(
    publicKey,
    Buffer.from(encodedSignature, 'base64url')
  )

  if (!isValid) {
    throw new Error('invalid_token')
  }

  const payload = JSON.parse(
    Buffer.from(encodedPayload, 'base64url').toString('utf8')
  ) as TPayload

  return { header, payload }
}


export function validateAccessTokenClaims(
  token: VerifiedJwt<AccessTokenPayload>,
  options: {
    expectedIssuer: string
    rejectDelegated?: boolean
    now?: number
  }
): AccessTokenPayload {

  const { expectedIssuer, rejectDelegated = false } = options
  const now = options.now ?? Math.floor(Date.now() / 1000)

  const payload = token.payload

  // Issuer must match
  if (payload.iss !== expectedIssuer) {
    throw new Error('invalid_token')
  }

  // Expiration must be valid
  if (typeof payload.exp !== 'number' || payload.exp <= now) {
    throw new Error('invalid_token')
  }

  // Subject must exist
  if (!payload.sub || typeof payload.sub !== 'string') {
    throw new Error('invalid_token')
  }

  // Optional: enforce single-level delegation
  if (rejectDelegated && payload.act) {
    throw new Error('invalid_grant')
  }

  return payload
}