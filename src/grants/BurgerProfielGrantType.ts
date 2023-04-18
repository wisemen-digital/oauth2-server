import OAuth2Server, { InvalidArgumentError } from '@node-oauth/oauth2-server'
import jwt, { JwtPayload } from 'jsonwebtoken'
import axios from 'axios'
import { importJWK, jwtVerify } from 'jose'
import { IBurgerProfielConfig, IBurgerProfielResponse, UserService } from '../types'
import { DefaultGrantType } from './DefaultGrantType'

export abstract class BurgerProfielGrantType extends DefaultGrantType {
  private static userService: UserService
  private static issuers: string[]

  public static configure (
    config: IBurgerProfielConfig,
    userService: UserService
  ): void {
    this.userService = userService
    this.issuers = config.issuers
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (request == null) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (client == null) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    if (request.body.id_token == null) {
      throw new InvalidArgumentError('Missing parameter: `id_token`')
    }

    const scope = this.getScope(request)

    const payload = await this.verifyToken(request.body.id_token)

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const user = await BurgerProfielGrantType.userService.createOrGetBurgerProfielUser!(payload)

    return await this.saveToken(user, client, scope)
  }

  async verifyToken (token: string): Promise<IBurgerProfielResponse> {
    const { payload, header } = jwt.decode(token, { complete: true }) as JwtPayload

    if (!BurgerProfielGrantType.issuers.includes(payload.iss)) {
      throw new InvalidArgumentError('Invalid issuer')
    }

    const configurationUrl = payload.iss as string + '/.well-known/openid-configuration'
    const configuration = await axios.get(configurationUrl).then(res => res.data)

    const keys = await axios.get(configuration.jwks_uri).then(res => res.data?.keys)

    const key = await importJWK(keys.find(key => key.kid === header.kid))

    await jwtVerify(token, key)

    return payload
  }
}
