import { randomUUID } from 'crypto'
import { InvalidArgumentError, InvalidRequestError, User } from '@node-oauth/oauth2-server'
import { CodeChallengeMethod, OAuth2Client } from 'google-auth-library'
import { GoogleConfig, GoogleGenerateAuthURLOptions, OAuth2Server, PKCEService, UserService } from '..'
import { DefaultGrantType } from './DefaultGrantType'

export abstract class GoogleGrantType extends DefaultGrantType {
  private static googleInstance: OAuth2Client
  private static userService: UserService
  private static redirectUri: string
  private static pkceService: PKCEService

  public static configure (
    config: GoogleConfig,
    userService: UserService,
    pkceService: PKCEService
  ): void {
    this.redirectUri = config.redirectUri
    this.pkceService = pkceService

    this.userService = userService
    this.googleInstance = new OAuth2Client({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri
    })
  }

  public static async createUrl (options: GoogleGenerateAuthURLOptions): Promise<string> {
    if (this.userService == null ||
        this.redirectUri == null ||
        this.googleInstance == null
    ) {
      throw new Error('GoogleGrantType not configured')
    }

    const verifier = await this.googleInstance.generateCodeVerifierAsync()
    if (verifier.codeChallenge == null) {
      throw new Error('Code challenge has not been generated')
    }

    const pkce = await this.pkceService.create({
      uuid: randomUUID(),
      challengeMethod: 'S256',
      challenge: verifier.codeChallenge,
      verifier: verifier.codeVerifier,
      csrfToken: randomUUID(),
      scopes: options.scopes
    })

    const state = Buffer.from(JSON.stringify({
      uuid: pkce.uuid,
      csrfToken: pkce.csrfToken
    })).toString('base64')

    const url = this.googleInstance.generateAuthUrl({
      access_type: options.accessType,
      scope: options.scopes,
      hd: options.hd ?? '*',
      login_hint: options.loginHint,
      response_type: 'CODE',
      code_challenge_method: CodeChallengeMethod.S256,
      code_challenge: pkce.challenge,
      redirect_uri: this.redirectUri,
      state
    })

    return url
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (request == null) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (client == null) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    if (request.body?.code == null) {
      throw new InvalidRequestError('Missing parameter: `code`')
    }

    const scope = this.getScope(request)

    const user = await this.verifyCode(request.body.code, request.body.state)

    if (user == null || user === false) {
      throw new InvalidRequestError('User not found')
    }

    return await this.saveToken(user, client, scope)
  }

  async verifyCode (code: string, state: string): Promise<false | User> {
    const pkce = await GoogleGrantType.pkceService.find(state)

    const authCodeRequest = {
      code,
      codeVerifier: pkce.verifier,
      redirectUri: GoogleGrantType.redirectUri
    }

    const tokenResponse = await GoogleGrantType.googleInstance.getToken(authCodeRequest)

    if (tokenResponse.tokens.id_token == null) {
      throw new Error('No id_token found in token response')
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return await GoogleGrantType.userService.findGoogleUser!(tokenResponse.tokens.id_token)
  }
}
