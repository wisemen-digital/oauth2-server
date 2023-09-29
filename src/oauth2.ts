import OAuth2Server, { OAuthError, RefreshToken, User } from '@node-oauth/oauth2-server'
import { AzureADGrantType } from './grants/AzureADGrantType'
import { Client, OAuth2ServerOptions, Token } from './types'
import { generateAuthorizationCodeModel } from './AuthorizationCodeModel'
import { AnonymousGrantType } from './grants/AnonymousGrantType'
import { BurgerProfielGrantType } from './grants/BurgerProfielGrantType'
import { WoningpasGrantType } from './grants/WoningpasGrantType'
import { GoogleGrantType } from './grants/GoogleGrantType'
import { AppleGrantType } from './grants/AppleGrantType'

export function createOAuth2 (options: OAuth2ServerOptions): OAuth2Server {
  const codeModel = generateAuthorizationCodeModel(options.services.codeService)
  const serverOptions: OAuth2Server.ServerOptions = {
    model: {
      getClient: async (clientId: string, secret: string) => {
        return await options.services.clientService.getClient(clientId, secret)
      },
      getUserFromClient: async (client: Client) => {
        return await options.services.clientService.getUserFromClient(client)
      },
      getUser: async (username, password) => {
        return await options.services.userService.verify(username, password)
      },
      generateAccessToken: async (client: Client, user, scope) => {
        return await options.services.tokenService.generateAccessToken(client, user, scope)
      },
      generateRefreshToken: async (client: Client, user, scope) => {
        return await options.services.tokenService.generateRefreshToken(client, user, scope)
      },
      getAccessToken: async (accessToken) => {
        return await options.services.tokenService.getAccessToken(accessToken)
      },
      getRefreshToken: async (refreshToken) => {
        return await options.services.tokenService.getRefreshToken(refreshToken)
      },
      revokeToken: async (token: RefreshToken | Token) => {
        return await options.services.tokenService.revokeToken(token)
      },
      saveToken: async (token: Token, client: Client, user: User): Promise<Token> => {
        token.client = client
        token.user = user

        if (token.refreshToken != null) {
          await options.services.tokenService.saveRefreshToken(token.refreshToken)
        }

        return token
      },
      verifyScope: async (token: Token, scope: string[]): Promise<boolean> => {
        if (token.scope == null) {
          return false
        }

        return scope.every(s => token.scope.includes(s))
      },
      validateScope: async (
        _user: User, client: Client, scope: string[]
      ): Promise<string[]> => {
        if (scope == null) {
          return []
        }

        const valid = scope.every(s => {
          if (client.scopes == null) {
            return false
          }
          return client.scopes.includes(s) && options.scopes.includes(s)
        })

        if (!valid) {
          throw new OAuthError('Invalid scope', {
            code: 400
          })
        }

        return scope
      },
      ...codeModel
    },
    accessTokenLifetime: options.services.tokenService.getAccessTokenLifetime(),
    refreshTokenLifetime: options.services.tokenService.getRefreshTokenLifetime()
  }

  serverOptions.extendedGrantTypes = options.extendedGrantTypes ?? {}

  if (options?.integrations?.ad != null) {
    if (options.services.pkceService == null) {
      throw new Error('PKCE service is required for Azure AD integration')
    }

    if (options.services.userService.findADUser == null) {
      throw new Error('User service must implement findADUser for Azure AD integration')
    }

    AzureADGrantType.configure(
      options.integrations.ad,
      options.services.pkceService,
      options.services.userService
    )

    serverOptions.extendedGrantTypes.ad = AzureADGrantType
  }

  if (options.integrations?.anonymous != null) {
    if (options.services.userService.createAnonymousUser == null) {
      throw new Error('User service must implement createAnonymousUser for Anonymous integration')
    }

    AnonymousGrantType.configure(
      options.services.userService
    )

    serverOptions.extendedGrantTypes.anonymous = AnonymousGrantType
  }

  if (options.integrations?.woningpas != null) {
    if (options.services.userService.createWoningpasUser == null) {
      throw new Error('User service must implement createWoningpasUser for Woningpas integration')
    }

    WoningpasGrantType.configure(
      options.services.userService
    )

    serverOptions.extendedGrantTypes.woningpas = WoningpasGrantType
  }

  if ((options.integrations?.burgerProfiel) != null) {
    if (options.services.userService.createOrGetBurgerProfielUser == null) {
      throw new Error('User service must implement createOrGetBurgerProfielUser for BurgerProfiel integration')
    }

    BurgerProfielGrantType.configure(
      options.integrations.burgerProfiel,
      options.services.userService
    )

    serverOptions.extendedGrantTypes.burgerProfiel = BurgerProfielGrantType
  }

  if (options.integrations?.google != null) {
    if (options.services.userService.createOrGetGoogleUser == null) {
      throw new Error('User service must implement createOrGetGoogleUser for Google integration')
    }

    GoogleGrantType.configure(
      options.services.userService
    )

    serverOptions.extendedGrantTypes.google = GoogleGrantType
  }

  if (options.integrations?.apple != null) {
    if (options.services.userService.createOrGetAppleUser == null) {
      throw new Error('User service must implement createOrGetAppleUser for Apple integration')
    }

    AppleGrantType.configure(
      options.services.userService
    )

    serverOptions.extendedGrantTypes.apple = AppleGrantType
  }

  return new OAuth2Server(serverOptions)
}
