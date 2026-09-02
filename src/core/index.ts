/**
 * @anephenix/fastify-auth/core
 *
 * The building blocks the five built-in strategies (sessions, magic-links,
 * mfa-sms, mfa-totp, forgotten-password) are themselves composed from -
 * exported so a custom login flow (e.g. the `fastify-auth wizard` CLI's
 * generated code, or your own hand-rolled combination) can reuse the same
 * security-sensitive logic (password checks, session creation, TOTP
 * encryption, MFA gating, reset-token validation) instead of re-implementing
 * it.
 */

export {
	type ResetTokenValidation,
	validateResetToken,
} from "./forgot-password.js";
export { issueMfaChallenge } from "./mfa-gate.js";
export { verifyPassword } from "./password.js";
export {
	createSession,
	respondWithNewSession,
	respondWithRefreshedSession,
	type SessionTokens,
} from "./session.js";
export {
	createDeleteAllSessionsHandler,
	createDeleteSessionHandler,
	createListSessionsHandler,
	createLogoutHandler,
	createProfileHandler,
	createRefreshHandler,
} from "./session-management.js";
export {
	buildTotpCrypto,
	type TotpCrypto,
	verifyRecoveryCode,
	verifyTotpCode,
} from "./totp.js";
