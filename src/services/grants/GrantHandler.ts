import { Client } from '../../domain/models.js'
import { TokenService } from '../services.js'

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
  handle(tokenService: TokenService, request: TokenRequest): Promise<TokenResponse>
}