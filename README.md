# express-oauth2

## Installation

```bash
npm install express-oauth2
```

## Adding a authentication method to your project

In order to add a new authentication method to your project, first add the new integration:

```typescript
export const oauth: OAuth2Server = createOAuth2({
        scopes: Object.values(Scope),
        services: {
          userService,
          clientService,
          tokenService
        },
        integrations: {
                google: true
                }
        })
```

Add the integration to the client grants in the client service:

```typescript
      client.grants = ['password', 'refresh_token', 'google']
```

Implement the integration user service method:

```typescript
  createOrGetGoogleUser?: (payload: IGoogleResponse) => Promise<User>
```

```typescript
  async createOrGetGoogleUser (payload: IGoogleResponse): Promise<User> {
    const user = await User.findOne({ where: { email: payload.email } })
    
    if (user != null) return user
    
    const newUser = User.create({
      email: payload.email,
      password: this.getRandomPassword()
    })
    
    await this.hashPassword(newUser, newUser.password)
    
    return await newUser.save()
  }
```
