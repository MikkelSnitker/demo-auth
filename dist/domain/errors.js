export class OAuthError extends Error {
    error;
    statusCode;
    constructor(error, statusCode = 400) {
        super(error);
        this.error = error;
        this.statusCode = statusCode;
    }
}
//# sourceMappingURL=errors.js.map