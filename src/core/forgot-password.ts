// Dependencies
import type { Auth } from "@anephenix/auth";
import type {
	IForgotPasswordModel,
	IForgotPasswordModelStatic,
} from "../types.js";

export type ResetTokenValidation =
	| { valid: true; record: IForgotPasswordModel }
	| { valid: false; error: string };

/*
  Looks up a ForgotPassword record by selector and validates it - not found,
  expired, already-used, and token-hash mismatch all report the same
  generic error (avoids leaking which failure mode occurred). Shared by
  GET /reset-password/:selector (just validates) and POST /reset-password
  (validates, then updates the password).
*/
export async function validateResetToken({
	ForgotPassword,
	auth,
	selector,
	token,
}: {
	ForgotPassword: IForgotPasswordModelStatic;
	auth: Auth;
	selector: string;
	token: string;
}): Promise<ResetTokenValidation> {
	const record = await ForgotPassword.query()
		.where("selector", selector)
		.first();

	if (!record) {
		return {
			valid: false,
			error: "Invalid reset password selector or token",
		};
	}
	if (record.expires_at < new Date()) {
		return { valid: false, error: "Password reset token has expired" };
	}
	if (record.used_at) {
		return {
			valid: false,
			error: "Password reset token has already been used",
		};
	}

	const isTokenValid = await auth.verifyPassword(token, record.token_hash);
	if (!isTokenValid) {
		return {
			valid: false,
			error: "Invalid reset password selector or token",
		};
	}

	return { valid: true, record };
}
