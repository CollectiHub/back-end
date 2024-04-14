package constants

const JsonValidationErrorMessage = "error happened during json validation"
const NotLoggedInErrorMessage = "you are not logged in"
const TokenIsNotValidErrorMessage = "token is not valid"
const UnexpectedErrorMessage = "unexpected error happened"
const PasswordHashingErrorMessage = "error happened during password hashing"
const DatabaseErrorMessage = "error occured during database operation"
const IncorrectPasswordErrorMessage = "incorrect password"
const TokenProcessingErrorMessage = "error occured during token processing"
const MaliciousActivityErrorMessage = "malicious activirt detected. All token will be wiped out. You will need to log in again using your credentials and password"
const IncorrectOAuthStateErrorMessage = "oauth state param is incorrect"
const OAuthExchangeErrorMessage = "oauth exchange failed"
const OAuthUserDataFetchErrorMessage = "oauth user data fetch failed"
const UserDataReadingErrorMessage = "user data reading failed"
const AccountIsAlreadyVerified = "account is already verified"
const WrongVerificationCodeErrorMessage = "wrong verification code"
const ForbiddenActionErrorMessage = "you are not allowed to perform this action"
const IncorrectIdErrorMessage = "incorrect id"

const SuccessMessage = "success"
const SuccessfulTokenRefreshMessage = "tokens were successfully refreshed"

func NotFoundMessage(entityName string) string {
	return entityName + " not found"
}
