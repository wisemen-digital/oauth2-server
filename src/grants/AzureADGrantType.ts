import { ConfidentialClientApplication, CryptoProvider, ResponseMode } from '@azure/msal-node';
import OAuth2Server, { InvalidArgumentError, InvalidRequestError } from '@node-oauth/oauth2-server';
import { randomUUID } from 'crypto';
import { AzureADConfig, PKCEService, UserService } from '../types';
import {DefaultGrantType} from "./DefaultGrantType";

const cryptoProvider = new CryptoProvider()

export abstract class AzureADGrantType extends DefaultGrantType {
  private static msalInstance: ConfidentialClientApplication
  private static pkceService: PKCEService
  private static userService: UserService
  private static redirectUri: string
  private static authority: string

  public static configure (
    config: AzureADConfig,
    pkceService: PKCEService,
    userService: UserService
  ) {
    this.redirectUri = config.redirectUri
    this.authority = config.cloudInstance + config.tenantId

    this.msalInstance = new ConfidentialClientApplication({
      auth: {
        clientId: config.clientId,
        authority: this.authority,
        clientSecret: config.clientSecret
      },
      system: {
        loggerOptions: {
          loggerCallback (loglevel, message, _containsPii) {
            // eslint-disable-next-line no-console
            console.log(message)
          },
          piiLoggingEnabled: false,
          logLevel: 2
        }
      }
    })

    this.pkceService = pkceService
    this.userService = userService
  }

  public static async createUrl (scopes: string[]): Promise<string> {
    if (!this.msalInstance || !this.pkceService || !this.userService || !this.redirectUri) {
      throw new Error('AzureADGrantType not configured')
    }

    const { verifier, challenge } = await cryptoProvider.generatePkceCodes()

    const pkce = await this.pkceService.create({
      uuid: randomUUID(),
      challengeMethod: 'S256',
      challenge: challenge,
      verifier: verifier,
      csrfToken: cryptoProvider.createNewGuid(),
      scopes: scopes
    })

    return await this.msalInstance.getAuthCodeUrl({
      redirectUri: this.redirectUri,
      responseMode: ResponseMode.QUERY,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: pkce.challengeMethod,
      state: cryptoProvider.base64Encode(JSON.stringify({
        uuid: pkce.uuid,
        csrfToken: pkce.csrfToken
      })),
      scopes: pkce.scopes
    })
  }

  public static async signoutUrl (redirectUri: string): Promise<string> {
    if (!this.msalInstance) {
      throw new Error('AzureADGrantType not configured')
    }

    const url = new URL(`${this.authority}/oauth2/v2.0/logout`)

    url.searchParams.append('post_logout_redirect_uri', redirectUri)

    return url.toString()
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (!request) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (!client) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    if (!request.body?.code) {
      throw new InvalidRequestError('Missing parameter: `code`')
    }

    const scope = this.getScope(request)

    const user = await this.verifyCode(request.body.code, request.body.state)

    if (!user) {
      throw new InvalidRequestError('User not found')
    }

    return this.saveToken(user, client, scope)
  }

  async verifyCode (code: string, state: string) {
    if (state == null) {
      throw new Error('state is null')
    }

    const decoded = JSON.parse(cryptoProvider.base64Decode(state))

    const pkce = await AzureADGrantType.pkceService.find(decoded.uuid)

    if (decoded.csrfToken !== pkce.csrfToken) {
      throw new Error('csrfToken does not match')
    }

    const authCodeRequest = {
      code: code,
      codeVerifier: pkce.verifier,
      redirectUri: AzureADGrantType.redirectUri,
      scopes: pkce.scopes
    }

    const tokenResponse = await AzureADGrantType.msalInstance.acquireTokenByCode(authCodeRequest)

    return await AzureADGrantType.userService.findADUser!(tokenResponse.uniqueId)
  }

}
