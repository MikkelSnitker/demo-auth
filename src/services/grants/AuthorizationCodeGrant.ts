import { GrantHandler, TokenRequest, TokenResponse } from './GrantHandler.js'
import {TokenService } from '../services.js'
import { OAuthError } from '../../domain/errors.js'

export class AuthorizationCodeGrant implements GrantHandler {

  supports(grantType: string): boolean {
    return grantType === 'authorization_code'
  }

  async handle(tokenService: TokenService, request: TokenRequest): Promise<TokenResponse> {

    const { client, params } = request

    const code = params.get('code')
    const redirectUri = params.get('redirect_uri')
    const codeVerifier = params.get('code_verifier')

    if (!code || !redirectUri || !codeVerifier) {
      throw new OAuthError('invalid_request')
    }

    return tokenService.exchangeCode(client, {
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    })
  }
}