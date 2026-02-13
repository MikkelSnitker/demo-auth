import { GrantHandler, TokenRequest, TokenResponse } from './GrantHandler.js'
import { exchangeRefresh } from '../services.js'
import { OAuthError } from '../../domain/errors.js'

export class RefreshGrant implements GrantHandler {

  supports(grantType: string): boolean {
    return grantType === 'refresh_token'
  }

  async handle(request: TokenRequest): Promise<TokenResponse> {

    const { client, params } = request
    const refreshToken = params.get('refresh_token')

    if (!refreshToken) {
      throw new OAuthError('invalid_request')
    }

    return exchangeRefresh(client, refreshToken)
  }
}