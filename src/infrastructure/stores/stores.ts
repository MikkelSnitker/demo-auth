import { AuthorizationCode, RefreshToken, Client } from '../../domain/models.js'

export const clients = new Map<string, Client>()
export const authCodes = new Map<string, AuthorizationCode>()
export const refreshTokens = new Map<string, RefreshToken>()
export const families = new Map<string, Set<string>>()
