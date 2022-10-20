import { RefreshToken, User } from '@node-oauth/oauth2-server'

export interface Client {
  id: string
  redirectUris?: string | string[]
  grants: string | string[]
  accessTokenLifetime?: number
  refreshTokenLifetime?: number
  scopes: string[]
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}


export interface Token {
  accessToken: string
  accessTokenExpiresAt: Date
  refreshToken?: string
  refreshTokenExpiresAt?: Date
  scope: string[]
  client: Client
  user: User
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}


export interface ClientService {
  getClient: (clientId: string, secret: string) => Promise<Client|false>
  getUserFromClient: (client: Client) => Promise<User | undefined>
}

export interface UserService {
  verify: (email: string, password: string) => Promise<User|false>
}

export interface TokenService {
  getAccessTokenLifetime: () => number
  getRefreshTokenLifetime: () => number
  getAccessToken: (accessToken: string) => Promise<Token | false>
  getRefreshToken: (refreshToken: string) => Promise<RefreshToken | false>
  generateAccessToken: (client: Client, user: User, scope: string | string[]) => Promise<string>
  generateRefreshToken: (client: Client, user: User, scope: string | string []) => Promise<string>
  saveRefreshToken: (refreshToken: string) => Promise<void>
  revokeToken: (token: RefreshToken | Token) => Promise<boolean>
}


export interface OAuth2ServerOptions {
  scopes: string[]
  clientService: ClientService
  userService: UserService
  tokenService: TokenService
}
