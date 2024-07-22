import OAuth2Server, { InvalidArgumentError } from '@node-oauth/oauth2-server'
import axios from 'axios'
import { base64url } from 'jose'
import { IAppleResponse, UserService } from '../types'
import { verifyJwtToken } from '../utils/verify-jwt-token.util'
import { DefaultGrantType } from './DefaultGrantType'

export abstract class AppleGrantType extends DefaultGrantType {
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
    const user = await AppleGrantType.userService.createOrGetAppleUser!(response)

    return await this.saveToken(user, client, scope)
  }

  async verifyToken (token: string): Promise<IAppleResponse> {
    const { data } = await axios.get('https://appleid.apple.com/auth/keys')
    const { keys } = data

    const headerBase64Url = token.split('.')[0]
    const header = JSON.parse(Buffer.from(headerBase64Url, 'base64').toString('utf8'))

    const matchingKey = keys.find((key) => key.kid === header.kid)

    if (matchingKey == null) throw new Error('No matching kid found.')

    verifyJwtToken(token, matchingKey)
    return JSON.parse(base64url.decode(token.split('.')[1]) as unknown as string)
  }
}
