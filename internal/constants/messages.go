package constants

const JsonValidationErrorMessage = "json_validation_error"
const NotLoggedInErrorMessage = "not_authenticated"
const TokenIsNotValidErrorMessage = "invalid_token"
const UnexpectedErrorMessage = "unexpected_error"
const PasswordHashingErrorMessage = "password_hashing_error"
const DatabaseErrorMessage = "database_operation_error"
const IncorrectPasswordErrorMessage = "incorrect_password"
const TokenProcessingErrorMessage = "token_processing_error"
const MaliciousActivityErrorMessage = "malicious_activity_detected"
const IncorrectOAuthStateErrorMessage = "incorrect_oauth_state_param"
const OAuthExchangeErrorMessage = "oauth_exchange_failed"
const OAuthUserDataFetchErrorMessage = "oauth_user_data_fetch_failed"
const UserDataReadingErrorMessage = "user_data_reading_failed"
const AccountIsAlreadyVerified = "account_is_already_verified"
const WrongVerificationCodeErrorMessage = "wrong_verification_code"
const ForbiddenActionErrorMessage = "action_forbidden"
const IncorrectIdErrorMessage = "incorrect_id"
const RarityIsRequiredErrorMessage = "rarity_is_required"
const FormDataDecodeErrorMessage = "form_data_decoding_error"
const FormDataExceedsLimitErrorMessage = "form_data_exceeds_limit"
const UploadingServiceErrorMessage = "uploading_service_error"

const SuccessMessage = "success"
const SuccessfulTokenRefreshMessage = "tokens_refreshed"

func NotFoundMessage(entityName string) string {
	return entityName + " not found"
}
