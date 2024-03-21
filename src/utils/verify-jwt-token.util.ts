import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'

export function verifyJwtToken (token: string, matchingKey: string): void {
  const pem = jwkToPem(matchingKey)

  try {
    jwt.verify(token, pem, { algorithms: ['RS256'] })
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token')
    } else if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token expired')
    } else {
      throw new Error('Unknown error while verifying token')
    }
  }
}
