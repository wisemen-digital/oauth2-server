import { AuthenticationResult } from '@azure/msal-node'
import {
  AbstractGrantType,
  AuthorizationCode,
  RefreshToken,
  User
} from '@node-oauth/oauth2-server'

export interface Client {
  id: string
  redirectUris?: string | string[]
  grants: string | string[]
  accessTokenLifetime?: number
  refreshTokenLifetime?: number
  scopes?: string[] | undefined
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}

export interface Token {
  accessToken: string
  accessTokenExpiresAt?: Date
  refreshToken?: string
  refreshTokenExpiresAt?: Date
  scopes?: string[] | undefined
  client: Client
  user: User
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}

export type AdAuthenticationResult = AuthenticationResult

export interface ClientService {
  getClient: (clientId: string, secret: string) => Promise<Client | false>
  getUserFromClient: (client: Client) => Promise<User | undefined>
}

export interface UserService {
  verify: (email: string, password: string, client: Client) => Promise<User | false>
  createAnonymousUser?: () => Promise<User>
  createWoningpasUser?: (clientUuid: string) => Promise<User>
  createOrGetBurgerProfielUser?: (payload: IBurgerProfielResponse) => Promise<User>
  createOrGetGoogleUser?: (payload: IGoogleResponse) => Promise<User>
  createOrGetAppleUser?: (payload: IAppleResponse) => Promise<User>
  findADUser?: (payload: AdAuthenticationResult) => Promise<User | false>
}

export interface TokenService {
  getAccessTokenLifetime: () => number
  getRefreshTokenLifetime: () => number
  getAccessToken: (accessToken: string) => Promise<Token | false>
  getRefreshToken: (refreshToken: string) => Promise<RefreshToken | false>
  generateAccessToken: (client: Client, user: User, scope: string[]) => Promise<string>
  generateRefreshToken: (client: Client, user: User, scope: string []) => Promise<string>
  saveRefreshToken: (refreshToken: string) => Promise<void>
  revokeToken: (token: RefreshToken | Token) => Promise<boolean>
}

export interface CodeService {
  generateAuthorizationCode?: (client: Client, user: User, scope: string []) => Promise<string>
  saveAuthorizationCode: (code: AuthorizationCode) => Promise<AuthorizationCode | false>
  getAuthorizationCode: (authorizationCode: string) => Promise<AuthorizationCode | false>
  revokeAuthorizationCode: (code: AuthorizationCode) => Promise<boolean>
}

export interface VerificationCodeService {
  verify: (key: string, code: number) => Promise<User | false>
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
    verificationCodeService?: VerificationCodeService
  }
  integrations?: {
    ad?: AzureADConfig
    anonymous?: boolean
    woningpas?: boolean
    burgerProfiel?: IBurgerProfielConfig
    google?: boolean
    apple?: boolean
    verificationCode?: boolean
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

export interface IBurgerProfielConfig {
  issuers: string[]
}

export interface IBurgerProfielResponse {
  at_hash: string
  aud: string
  azp: string
  cot: string
  exp: number
  family_name: string
  given_name: string
  iat: number
  iss: string
  kid: string
  sub: string
  vo_email?: string
  vo_orgcode?: string
  vo_orgnaam?: string
}

export interface IGoogleResponse {
  iss: string
  azp: string
  aud: string
  sub: string
  hd: string
  email?: string
  email_verified: boolean
  name: string
  picture: string
  given_name: string
  family_name: string
  locale: string
  iat: number
  exp: number
}

export interface IAppleResponse {
  iss: string
  aud: string
  exp: number
  iat: number
  sub: string
  c_hash: string
  email?: string
  email_verified: string
  is_private_email: string
  auth_time: number
  nonce_supported: boolean
}
