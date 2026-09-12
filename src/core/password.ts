// Dependencies
import type { Auth } from "@anephenix/auth";
import type { IUserModel, IUserModelStatic } from "../types.js";

/**
 * Thrown by verifyPassword() when the account has made too many failed
 * attempts within auth.loginWindowSeconds. Strategies catch this
 * specifically and respond 429 with a Retry-After header instead of the
 * generic 401 used for invalid credentials.
 */
export class RateLimitedError extends Error {
	readonly retryAfter: number;

	constructor(retryAfter: number) {
		super(
			`Too many login attempts. Please try again in ${retryAfter} seconds.`,
		);
		this.name = "RateLimitedError";
		this.retryAfter = retryAfter;
	}
}

function windowHasExpired(auth: Auth, user: IUserModel | undefined | null) {
	if (!user?.failed_login_window_started_at) return true;
	const startedAt = new Date(user.failed_login_window_started_at).getTime();
	return Date.now() - startedAt >= auth.loginWindowSeconds * 1000;
}

/*
  Validates that both an identifier and password were supplied, then
  performs the shared first-factor check used by sessions ('/login'),
  mfa-sms ('/sessions') and mfa-totp ('/login', plus its MFA-disable
  routes) - itself, rather than delegating to the model:

  - looks the user up via User.findByIdentifier()
  - enforces the login rate limit (auth.checkRateLimit), throwing
    RateLimitedError if the account is currently locked out
  - performs a timing-safe password comparison (auth.verifyPasswordSafe),
    so response time doesn't reveal whether the identifier exists
  - tracks failed_login_attempts / failed_login_window_started_at on the
    user record, resetting them on success

  Centralising this here means every strategy gets the same protection
  automatically, instead of depending on each model reimplementing it
  correctly.
*/
export async function verifyPassword(
	auth: Auth,
	User: IUserModelStatic,
	identifier: string,
	password: string,
): Promise<(IUserModel & { isUsingMFA?: boolean }) | null> {
	if (!identifier) {
		throw new Error("Please provide your username or email address");
	}
	if (!password) throw new Error("Password is required");

	const user = await User.findByIdentifier(identifier);
	const windowExpired = windowHasExpired(auth, user);

	if (user && !windowExpired) {
		const status = auth.checkRateLimit({
			attempts: user.failed_login_attempts ?? 0,
			firstAttemptAt: user.failed_login_window_started_at as string | Date,
		});
		if (status.blocked) {
			throw new RateLimitedError(status.retryAfter ?? auth.loginWindowSeconds);
		}
	}

	const isAuthenticated = await auth.verifyPasswordSafe(
		password,
		user?.hashed_password,
	);

	if (isAuthenticated && user) {
		if ((user.failed_login_attempts ?? 0) > 0) {
			await user.$query().patch({
				failed_login_attempts: 0,
				failed_login_window_started_at: null,
			});
		}
		return Object.assign(user, {
			isUsingMFA: !!user.mfa_totp_secret,
		});
	}

	if (user) {
		await user.$query().patch({
			failed_login_attempts: windowExpired
				? 1
				: (user.failed_login_attempts ?? 0) + 1,
			failed_login_window_started_at: windowExpired
				? new Date().toISOString()
				: user.failed_login_window_started_at,
		});
	}

	return null;
}
