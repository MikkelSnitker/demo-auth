import { OAuthError } from "../../domain/errors.js"
import { exchangeToken } from "../services.js"
import { GrantHandler, TokenRequest, TokenResponse } from "./GrantHandler"


export class TokenExchangeGrant implements GrantHandler {

  supports(grantType: string): boolean {
    return grantType === 'urn:ietf:params:oauth:grant-type:token-exchange'
  }

  async handle(request: TokenRequest): Promise<TokenResponse> {
    const { client, params } = request

    if (!client.allowTokenExchange) {
      throw new OAuthError('unauthorized_client')
    }
    if (params.get('actor_token_type') !== 'urn:ietf:params:oauth:token-type:id_token' || params.get('subject_token_type') !== 'urn:ietf:params:oauth:token-type:access_token') {
      throw new OAuthError('invalid_request')
    }
    let actor;
    try {
      actor = JSON.parse(params.get('actor_token')!)
      if (typeof actor !== 'object' || typeof actor.sub !== 'string') {
        throw new OAuthError('invalid_request')
      }
    } catch (err) {
       throw new OAuthError('invalid_request')
    }
    const subjectToken = params.get('subject_token')
    
    const scopeParam = params.get('scope')

    if (!subjectToken || !actor) {
      throw new OAuthError('invalid_request')
    }

    const requestedScope = scopeParam
      ? scopeParam.split(' ').filter(Boolean)
      : undefined

    const result = exchangeToken(
      client,
      subjectToken,
      actor,
      requestedScope
    )

    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    }
  }
}
