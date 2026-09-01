// Dependencies
import type { Auth } from "@anephenix/auth";
import type { IMfaTokenModelStatic } from "../types.js";

/*
  Issues a short-lived MFA token for a user who passed their first factor
  (password) but still needs to complete a second factor - persists it via
  the MfaToken model and returns the lookup token to hand back to the
  client. Used by mfa-totp's '/login' when the user has MFA enabled.
*/
export async function issueMfaChallenge(
	MfaToken: IMfaTokenModelStatic,
	auth: Auth,
	userId: string | number,
): Promise<{ token: string }> {
	const { token, expiresAt } = await auth.generateMfaLoginToken();

	await MfaToken.query().insert({
		user_id: userId,
		token,
		expires_at: expiresAt.toISOString(),
		number_of_attempts: 0,
	});

	return { token };
}
