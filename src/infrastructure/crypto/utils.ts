import { randomBytes, createHash, timingSafeEqual } from 'crypto'

export function base64url(input: Buffer) {
  return input.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

export function randomId() {
  return base64url(randomBytes(32))
}

export function sha256(input: string) {
  return base64url(createHash('sha256').update(input).digest())
}

export function computeAtHash(accessToken: string) {
  const digest = createHash('sha256').update(accessToken).digest()
  return base64url(digest.slice(0, digest.length / 2))
}

export function constantEqual(a: string, b: string) {
  const A = Buffer.from(a)
  const B = Buffer.from(b)
  if (A.length !== B.length) return false
  return timingSafeEqual(A, B)
}
