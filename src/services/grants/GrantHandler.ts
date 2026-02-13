import { Client } from '../../domain/models.js'

export interface TokenRequest {
  client: Client
  params: URLSearchParams
}

export interface TokenResponse {
  accessToken: string
  refreshToken?: string | undefined
  idToken?: string | undefined
}

export interface GrantHandler {
  supports(grantType: string): boolean
  handle(request: TokenRequest): Promise<TokenResponse>
}