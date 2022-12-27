import OAuth2Server, {
  AbstractGrantType,
  AuthorizationCode,
  AuthorizationCodeModel,
  RefreshToken,
  User
} from '@node-oauth/oauth2-server'

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
  findADUser?: (id: string) => Promise<User|false>
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

export interface CodeService {
  generateAuthorizationCode?: (client: Client, user: User, scope: string []) => Promise<string>
  saveAuthorizationCode: (code: AuthorizationCode) =>  Promise<AuthorizationCode | false>
  getAuthorizationCode: (authorizationCode: string) => Promise<AuthorizationCode | false>
  revokeAuthorizationCode: (code: AuthorizationCode) => Promise<boolean>
}

export interface PKCEService {
  find: (state: string) => Promise<PKCEType>
  create: (pkce: PKCEType) => Promise<PKCEType>
}

export interface OAuth2ServerOptions {
  scopes: string[]
  services: {
    clientService: ClientService
    userService: UserService
    tokenService: TokenService
    pkceService?: PKCEService
    codeService?: CodeService
  }
  integrations?: {
    ad?: AzureADConfig
  }
  extendedGrantTypes?: Record<string, typeof AbstractGrantType>
}

export interface PKCEType {
  uuid: string
  challengeMethod: string
  challenge: string
  verifier: string
  csrfToken: string | null
  scopes: string[]
}

export interface AzureADConfig {
  clientId: string
  tenantId: string
  cloudInstance: string
  clientSecret: string
  redirectUri: string
}
