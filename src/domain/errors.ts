export class OAuthError extends Error {
  constructor(
    public readonly error: string,
    public readonly statusCode: number = 400
  ) {
    super(error)
  }
}
