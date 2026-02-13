import { createSign } from 'crypto';
import { base64url } from './utils.js';
export function signJwt(payload, privateKey, kid) {
    const header = { alg: 'RS256', typ: 'JWT', kid };
    const encodedHeader = base64url(Buffer.from(JSON.stringify(header)));
    const encodedPayload = base64url(Buffer.from(JSON.stringify(payload)));
    const data = `${encodedHeader}.${encodedPayload}`;
    const signer = createSign('RSA-SHA256');
    signer.update(data);
    signer.end();
    const sig = signer.sign(privateKey);
    return `${data}.${base64url(sig)}`;
}
//# sourceMappingURL=jwt.js.map