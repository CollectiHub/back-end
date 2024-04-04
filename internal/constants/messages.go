package constants

const JsonValidationErrorMessage = "Error happened during json validation"
const NotLoggedInErrorMessage = "You are not logged in"
const TokenIsNotValidErrorMessage = "Token is not valid"
const UnexpectedErrorMessage = "Unexpected error happened"
const PasswordHashingErrorMessage = "Error happened during password hashing"
const DatabaseErrorMessage = "Error occured during database operation"
const IncorrectPasswordErrorMessage = "Incorrect password"
const TokenProcessingErrorMessage = "Error occured during token processing"
const MaliciousActivityErrorMessage = "Malicious activirt detected. All token will be wiped out. You will need to log in again using your credentials and password"
const IncorrectOAuthStateErrorMessage = "OAuth state param is incorrect"
const OAuthExchangeErrorMessage = "OAuth exchange failed"
const OAuthUserDataFetchErrorMessage = "OAuth user data fetch failed"
const UserDataReadingErrorMessage = "User data reading failed"
const AccountIsAlreadyVerified = "Account is already verified"

const SuccessMessage = "Success"
const SuccessfulTokenRefreshMessage = "Tokens were successfully refreshed"

func NotFoundMessage(entityName string) string {
	return entityName + " not found"
}
