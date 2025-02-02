import { type ApiRequest, Oauth2Driver } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'

import type {
  ApiRequestContract,
  RedirectRequestContract
} from '@adonisjs/ally/types'

import type {
  AllyDriverContract,
  LiteralStringUnion,
  Oauth2DriverConfig
} from '@adonisjs/ally/types'

export interface MicrosoftDriverContract
  extends AllyDriverContract<MicrosoftToken, MicrosoftScopes> {
  version: 'oauth2'
}

export type MicrosoftDriverConfig = Oauth2DriverConfig & {
  scopes?: LiteralStringUnion<MicrosoftScopes>[]
  prompt?: 'none' | 'consent' | 'select_account' | 'login'
}

export type MicrosoftToken = {
  expiresAt: Date
  expiresIn: number
  refreshToken: string
  scope: string[]
  token: string
  type: 'bearer'
}

export type MicrosoftScopes =
  | 'openid'
  | 'email'
  | 'profile'
  | 'Calendars.Read'
  | 'Calendars.Read.Shared'
  | 'Calendars.ReadBasic'
  | 'Calendars.ReadWrite'
  | 'Calendars.ReadWrite.Shared'

export class MicrosoftDriver extends Oauth2Driver<
  MicrosoftToken,
  MicrosoftScopes
> {
  protected authorizeUrl =
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'

  protected accessTokenUrl =
    'https://login.microsoftonline.com/common/oauth2/v2.0/token'

  protected userInfoUrl = 'https://graph.microsoft.com/oidc/userinfo'

  protected codeParamName = 'code'

  protected errorParamName = 'error'

  protected stateCookieName = 'microsoft_oauth_state'

  protected stateParamName = 'state'

  protected scopeParamName = 'scope'

  protected scopesSeparator = ' '

  constructor(ctx: HttpContext, public config: MicrosoftDriverConfig) {
    super(ctx, config)

    this.loadState()
  }

  protected configureRedirectRequest(
    request: RedirectRequestContract<MicrosoftScopes>
  ) {
    request.scopes(this.config.scopes || ['openid'])
    request.param('prompt', this.config.prompt)
    request.param('response_type', 'code')
  }

  protected configureAccessTokenRequest(request: ApiRequest): void {
    request
      .header('Content-Type', 'application/x-www-form-urlencoded')
      .field('grant_type', 'authorization_code')
      .field('client_id', this.config.clientId)
      .field('client_secret', this.config.clientSecret)
      .field('code', this.ctx.request.input(this.codeParamName))
  }

  /**
   * Find if the current error code is for access denied
   */
  accessDenied(): boolean {
    const error = this.getError()
    if (!error) {
      return false
    }

    return error === 'access_denied'
  }

  /**
   * Returns details for the authorized user
   */
  async user(callback?: (request: ApiRequestContract) => void) {
    const accessToken = await this.accessToken(callback)
    const user = await this.getUserInfo(accessToken.token, callback)
    return {
      ...user,
      token: accessToken
    }
  }

  /**
   * Finds the user by the access token
   */
  async userFromToken(
    token: string,
    callback?: (request: ApiRequestContract) => void
  ) {
    const user = await this.getUserInfo(token, callback)

    return {
      ...user,
      token: { token: token, type: 'bearer' as const }
    }
  }

  /**
   * Fetches the user info from the Twitch API
   */
  protected async getUserInfo(
    accessToken: string,
    callback?: (request: ApiRequest) => void
  ) {
    const request = this.getAuthenticatedRequest(this.userInfoUrl, accessToken)

    if (typeof callback === 'function') {
      callback(request)
    }

    const response = await request.get()
    return {
      id: response.sub,
      name: response.givenname,
      nickName: response.givenname,
      email: response.email,
      avatarUrl: response.picture,
      emailVerificationState: 'unsupported' as const,
      original: response
    }
  }

  /**
   * Returns the HTTP request with the authorization header set
   */
  protected getAuthenticatedRequest(url: string, token: string) {
    const request = this.httpClient(url)
    request.header('Authorization', `Bearer ${token}`)
    request.parseAs('json')
    return request
  }
}
export function microsoft(
  config: MicrosoftDriverConfig
): (ctx: HttpContext) => MicrosoftDriver {
  return (ctx) => new MicrosoftDriver(ctx, config)
}

module.exports = microsoft
