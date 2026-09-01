// Dependencies
import type { IUserModelStatic } from "../types.js";

/*
  Validates that both an identifier and password were supplied, then
  delegates to the model's own authenticate() - the shared first-factor
  check used by sessions ('/login'), mfa-sms ('/sessions') and mfa-totp
  ('/login').
*/
export async function verifyPassword(
	User: IUserModelStatic,
	identifier: string,
	password: string,
) {
	if (!identifier) {
		throw new Error("Please provide your username or email address");
	}
	if (!password) throw new Error("Password is required");

	return await User.authenticate({ identifier, password });
}
