export interface Client {
  id: string
  secret: string
  redirectUris: string[]
  scopes: string[]
  refreshTokenLifetimeSeconds?: number
  allowTokenExchange?: boolean
  //allowDelegation?: boolean
}
export interface AuthorizationCode {
  code: string
  clientId: string
  userId: string
  redirectUri: string
  scope: string[]
  codeChallenge: string
  nonce?: string | undefined;
  authTime: number
  expiresAt: number
}
export interface RefreshToken {
  id: string
  clientId: string
  userId: string
  scope: string[]
  expiresAt: number
  rootId: string
  parentId?: string
  used: boolean
  revoked: boolean
  act?: { sub: string } | undefined;
  delegatedFrom?: string| undefined
}
