import OAuth2Server, {InvalidArgumentError} from "@node-oauth/oauth2-server";
import {IBurgerProfielResponse, UserService} from "../types";
import {DefaultGrantType} from "./DefaultGrantType";
import jwt, { JwtPayload } from 'jsonwebtoken'
import axios from "axios";
import {importJWK, jwtVerify} from "jose";

export abstract class BurgerProfielGrantType extends DefaultGrantType {
  private static userService: UserService
  private static issuers: string[]

  public static configure (userService: UserService, issuers: string[]) {
      this.userService = userService
        this.issuers = issuers
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (!request) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (!client) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    const scope = this.getScope(request)

    const payload:IBurgerProfielResponse = await this.verifyToken(request.body.id_token)

    const user = await BurgerProfielGrantType.userService.createOrGetBurgerProfielUser(payload)

    return this.saveToken(user, client, scope)
  }

  async verifyToken (token: string) {
    const { payload, header } = jwt.decode(token, { complete: true }) as JwtPayload

    if (!BurgerProfielGrantType.issuers.includes(payload.iss)) {
      throw new InvalidArgumentError('Invalid issuer')
    }

    const configurationUrl = payload.iss + '/.well-known/openid-configuration'
    const configuration = await axios.get(configurationUrl).then(res => res.data)

    const keys = await axios.get(configuration.jwks_uri).then(res => res.data?.keys)

    const key = await importJWK(keys.find(key => key.kid === header.kid))

    await jwtVerify(token, key)

    return payload
  }
}
