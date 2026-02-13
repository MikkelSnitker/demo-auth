export interface Client {
  id: string
  secret: string
  redirectUris: string[]
  scopes: string[]
  refreshTokenLifetimeSeconds?: number
}

export interface AuthorizationCode {
  code: string
  clientId: string
  userId: string
  redirectUri: string
  scope: string[]
  codeChallenge: string
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
}
