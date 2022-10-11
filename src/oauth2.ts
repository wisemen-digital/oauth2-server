import OAuth2Server, { OAuthError, RefreshToken, User } from '@node-oauth/oauth2-server'
import { Client, OAuth2ServerOptions, Token } from './types'

export function createOAuth2 (options: OAuth2ServerOptions): OAuth2Server {
  const oauth = new OAuth2Server({
    model: {
      getClient: async (clientId: string, secret: string) => {
        return await options.clientService.getClient(clientId, secret)
      },
      getUserFromClient: async (client: Client) => {
        return await options.clientService.getUserFromClient(client)
      },
      getUser: async (username, password) => {
        return await options.userService.verify(username, password)
      },
      generateAccessToken: async (client: Client, user, scope) => {
        return await options.tokenService.generateAccessToken(client, user, scope)
      },
      generateRefreshToken: async (client: Client, user, scope) => {
        return await options.tokenService.generateRefreshToken(client, user, scope)
      },
      getAccessToken: async (accessToken) => {
        return await options.tokenService.getAccessToken(accessToken)
      },
      getRefreshToken: async (refreshToken) => {
        return await options.tokenService.getRefreshToken(refreshToken)
      },
      revokeToken: async (token: RefreshToken | Token) => {
        return await options.tokenService.revokeToken(token)
      },
      saveToken: async (token: Token, client: Client, user: User): Promise<Token> => {
        token.client = client
        token.user = user

        if (token.refreshToken != null) {
          await options.tokenService.saveRefreshToken(token.refreshToken)
        }

        return token
      },
      verifyScope: async (token: Token, scope: string | string[]): Promise<boolean> => {
        if (token.scope === null || token.scope === undefined) {
          return false
        }

        if (typeof scope === 'string') {
          scope = scope.split(' ')
        }

        return scope.every(s => token.scope.includes(s))
      },
      validateScope: async (
        _user: User, client: Client, scope: string | string[]
      ): Promise<string[]> => {
        if (scope === null || scope === undefined) {
          return []
        }

        if (typeof scope === 'string') {
          scope = scope.split(' ')
        }

        const valid = scope.every(s => {
          return client.scopes.includes(s) && options.scopes.includes(s)
        })

        if (!valid) {
          throw new OAuthError('Invalid scope', {
            code: 400
          })
        }

        return scope
      }
    },
    accessTokenLifetime: options.tokenService.getAccessTokenLifetime(),
    refreshTokenLifetime: options.tokenService.getRefreshTokenLifetime()
  })

  return oauth
}
