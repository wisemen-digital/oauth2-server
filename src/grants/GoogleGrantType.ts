import OAuth2Server, { InvalidArgumentError } from '@node-oauth/oauth2-server'
import axios from 'axios'
import { base64url } from 'jose'
import { IGoogleConfig, IGoogleResponse, UserService } from '../types'
import { verifyJwtToken } from '../utils/verify-jwt-token.util'
import { DefaultGrantType } from './DefaultGrantType'

export abstract class GoogleGrantType extends DefaultGrantType {
  private static userService: UserService
  private static googleClientId: string
  private static googleClientSecret: string
  private static redirectUri: string

  public static configure (userService: UserService, googleConfig: IGoogleConfig): void {
    this.userService = userService
    this.googleClientId = googleConfig.clientId
    this.googleClientSecret = googleConfig.clientSecret
    this.redirectUri = googleConfig.redirectUri
  }

  public async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (request == null) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (client == null) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    const scope = this.getScope(request)

    const response = await this.verifyToken(request.body.token)

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const user = await GoogleGrantType.userService.createOrGetGoogleUser!(response)

    return await this.saveToken(user, client, scope)
  }

  private async getGoogleToken (code: string): Promise<void> {
    const postObject = {
      code,
      client_id: GoogleGrantType.googleClientId,
      client_secret: GoogleGrantType.googleClientSecret,
      redirect_uri: GoogleGrantType.redirectUri,
      grant_type: 'authorization_code'
    }
    const googleToken = await axios.post('https://oauth2.googleapis.com/token', postObject)

    const postParams = new URLSearchParams({
      client_id: GoogleGrantType.googleClientId,
      client_secret: GoogleGrantType.googleClientSecret,
      scope: 'read write',
      token: googleToken.data.id_token,
      grant_type: 'google'
    })

    await axios.post('/auth/token', postParams, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    })
  }

  private async verifyToken (token: string): Promise<IGoogleResponse> {
    const { data } = await axios.get('https://www.googleapis.com/oauth2/v3/certs')
    const { keys } = data

    const headerBase64Url = token.split('.')[0]
    const header = JSON.parse(base64url.decode(headerBase64Url) as unknown as string)

    const matchingKey = keys.find((key) => key.kid === header.kid)

    if (matchingKey == null) {
      throw new Error('No matching kid found')
    }

    verifyJwtToken(token, matchingKey)
    return JSON.parse(base64url.decode(token.split('.')[1]) as unknown as string)
  }
}
