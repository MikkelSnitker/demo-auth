import { randomBytes, createHash, timingSafeEqual } from 'crypto';
export function base64url(input) {
    return input.toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}
export function randomId() {
    return base64url(randomBytes(32));
}
export function sha256(input) {
    return base64url(createHash('sha256').update(input).digest());
}
export function constantEqual(a, b) {
    const A = Buffer.from(a);
    const B = Buffer.from(b);
    if (A.length !== B.length)
        return false;
    return timingSafeEqual(A, B);
}
//# sourceMappingURL=utils.js.map