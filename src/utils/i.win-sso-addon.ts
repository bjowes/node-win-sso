export interface IWinSsoAddon {
    createAuthContext(
        securityPackage: string,
        targetHost: string | undefined,
        applicationData: Buffer,
        flags: number | undefined
    ): number,

    freeAuthContext(authContextId: number): void,

    getLogonUserName(): string,

    createAuthRequest(authContextId: number): Buffer,
    createAuthResponse(authContextId: number, inToken: Buffer): Buffer,
}