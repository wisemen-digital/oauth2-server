import OAuth2Server, { InvalidArgumentError } from '@node-oauth/oauth2-server'
import { VerificationCodeService } from '../types'
import { DefaultGrantType } from './DefaultGrantType'

export abstract class VerificationCodeGrantType extends DefaultGrantType {
  private static codeService: VerificationCodeService

  public static configure (codeService: VerificationCodeService): void {
    this.codeService = codeService
  }

  async handle (request: OAuth2Server.Request, client: OAuth2Server.Client): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    if (request == null) {
      throw new InvalidArgumentError('Missing parameter: `request`')
    }

    if (client == null) {
      throw new InvalidArgumentError('Missing parameter: `client`')
    }

    const scope = this.getScope(request)

    const { phoneNumber, code } = request.body
    const user = await VerificationCodeGrantType.codeService.verify(phoneNumber, code)

    if (user === false) {
      throw Error('Invalid code')
    }

    return await this.saveToken(user, client, scope)
  }
}
