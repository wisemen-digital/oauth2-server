import {Client, CodeService} from "./types";
import OAuth2Server, {AuthorizationCode, AuthorizationCodeModel, Falsey, User} from "@node-oauth/oauth2-server";

export type CodeModel = Pick<AuthorizationCodeModel, 'saveAuthorizationCode' | 'getAuthorizationCode' | 'revokeAuthorizationCode'>


export function generateAuthorizationCodeModel(service: CodeService | undefined): CodeModel | undefined  {
    if(service === undefined){
        return  undefined
    }
    return {
        getAuthorizationCode: async (code: string): Promise<AuthorizationCode | Falsey> => {
            return await service.getAuthorizationCode(code)
        },
        revokeAuthorizationCode: async (code: AuthorizationCode): Promise<boolean> => {
            return await service.revokeAuthorizationCode(code)
        },
        saveAuthorizationCode: async (
            code: Pick<AuthorizationCode, "authorizationCode" | "expiresAt" | "redirectUri" | "scope">,
            client: Client,
            user: User
        ): Promise<AuthorizationCode | Falsey> => {
            if (typeof code.scope === 'string') {
                code.scope = code.scope.split(' ')
            }
            const authorizationCode: AuthorizationCode = {
                authorizationCode: code.authorizationCode,
                expiresAt: code.expiresAt,
                redirectUri: code.redirectUri,
                scope: code.scope,
                user: user,
                client: client,
            }
            return await service.saveAuthorizationCode(authorizationCode)
        },
    }
}
