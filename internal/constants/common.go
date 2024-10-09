package constants

// Cookie names
const AccessTokenCookie = "access_token"
const RefreshTokenCookie = "refresh_token"

// Context keys
type ContextKey string

const CurrentUserContext = ContextKey("currentUser")

// Api routes
const MainRoute = "api/v1"

// Codes
const EmailVerificationCodeLength = 5
const PasswordresetVerificationCodeLength = 6
