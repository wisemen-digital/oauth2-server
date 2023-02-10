import OAuth2Server, {InvalidArgumentError} from "@node-oauth/oauth2-server";
import {UserService} from "../types";
import {DefaultGrantType} from "./DefaultGrantType";

export abstract class AnonymousGrantType extends DefaultGrantType {
  private static userService: UserService

  public static configure (userService: UserService) {
      this.userService = userService
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (!request) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (!client) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    const scope = this.getScope(request)

    const user = await AnonymousGrantType.userService.createAnonymousUser!()

    return this.saveToken(user, client, scope)
  }
}
