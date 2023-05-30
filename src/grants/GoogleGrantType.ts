import OAuth2Server, { InvalidArgumentError } from '@node-oauth/oauth2-server'
import axios from 'axios'
import { base64url } from 'jose'
import { IGoogleResponse, UserService } from '../types'
import { DefaultGrantType } from './DefaultGrantType'

export abstract class GoogleGrantType extends DefaultGrantType {
  private static userService: UserService

  public static configure (userService: UserService): void {
    this.userService = userService
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
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

  async verifyToken (token: string): Promise<IGoogleResponse> {
    const { data } = await axios.get('https://www.googleapis.com/oauth2/v3/certs')
    const { keys } = data

    const headerBase64Url = token.split('.')[0]
    const header = JSON.parse(base64url.decode(headerBase64Url) as unknown as string)

    const matchingKey = keys.find((key) => key.kid === header.kid)

    if (matchingKey == null) {
      throw new Error('No matching kid found.')
    }

    return JSON.parse(base64url.decode(token.split('.')[1]) as unknown as string)
  }
}
