import { AuthorizationCode, AuthorizationCodeModel, Falsey, User } from '@node-oauth/oauth2-server'
import { Client, CodeService } from './types'

export type CodeModel = Pick<
AuthorizationCodeModel,
'saveAuthorizationCode'
| 'getAuthorizationCode'
| 'revokeAuthorizationCode'
| 'generateAuthorizationCode'
>

export function generateAuthorizationCodeModel (service: CodeService | undefined): CodeModel | undefined {
  if (service === undefined) {
    return undefined
  }

  if (service.generateAuthorizationCode !== undefined) {
    return {
      generateAuthorizationCode: async (client: Client, user: User, scope: string[]): Promise<string> => {
        // @ts-expect-error can never be undefined because of check above
        return await service.generateAuthorizationCode(client, user, scope)
      },
      getAuthorizationCode: async (code: string): Promise<AuthorizationCode | Falsey> => {
        return await service.getAuthorizationCode(code)
      },
      revokeAuthorizationCode: async (code: AuthorizationCode): Promise<boolean> => {
        return await service.revokeAuthorizationCode(code)
      },
      saveAuthorizationCode: async (
        code: Pick<AuthorizationCode, 'authorizationCode' | 'expiresAt' | 'redirectUri' | 'scope'>,
        client: Client,
        user: User
      ): Promise<AuthorizationCode | Falsey> => {
        const authorizationCode: AuthorizationCode = {
          authorizationCode: code.authorizationCode,
          expiresAt: code.expiresAt,
          redirectUri: code.redirectUri,
          scope: code.scope,
          user,
          client
        }
        return await service.saveAuthorizationCode(authorizationCode)
      }
    }
  } else {
    return {
      generateAuthorizationCode: undefined,
      getAuthorizationCode: async (code: string): Promise<AuthorizationCode | Falsey> => {
        return await service.getAuthorizationCode(code)
      },
      revokeAuthorizationCode: async (code: AuthorizationCode): Promise<boolean> => {
        return await service.revokeAuthorizationCode(code)
      },
      saveAuthorizationCode: async (
        code: Pick<AuthorizationCode, 'authorizationCode' | 'expiresAt' | 'redirectUri' | 'scope'>,
        client: Client,
        user: User
      ): Promise<AuthorizationCode | Falsey> => {
        const authorizationCode: AuthorizationCode = {
          authorizationCode: code.authorizationCode,
          expiresAt: code.expiresAt,
          redirectUri: code.redirectUri,
          scope: code.scope,
          user,
          client
        }
        return await service.saveAuthorizationCode(authorizationCode)
      }
    }
  }
}
