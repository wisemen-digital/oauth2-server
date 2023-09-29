import OAuth2Server, { AbstractGrantType } from '@node-oauth/oauth2-server'

export abstract class DefaultGrantType extends AbstractGrantType {
  protected async saveToken (user: OAuth2Server.User, client: OAuth2Server.Client, scope: string[]): Promise<OAuth2Server.Token | OAuth2Server.Falsey> {
    const validatedScope = await this.validateScope(user, client, scope)

    if (
      validatedScope == null ||
      validatedScope === false ||
      validatedScope === 0 ||
      validatedScope === ''
    ) {
      return false
    }

    const accessToken = await this.generateAccessToken(client, user, validatedScope)
    const accessTokenExpiresAt = this.getAccessTokenExpiresAt()
    const refreshToken = await this.generateRefreshToken(client, user, scope)
    const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt()

    // todo: open issue on @node-oauth/oauth2-server for missing type
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const that = this as any

    return that.model.saveToken({
      accessToken,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
      scope: validatedScope
    }, client, user)
  }
}
