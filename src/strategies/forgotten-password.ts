import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { validateResetToken } from "../core/forgot-password.js";
import type { AuthFastifyPluginOptions } from "../types.js";

const isEmail = (value: string): boolean =>
	/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

// Rejects identifiers that contain characters outside of a valid email or
// username character set – stops obviously malformed input early.
const IDENTIFIER_RE =
	/^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9_-]+)$/;

/**
 * Registers the forgotten-password / reset-password route set:
 *
 *   POST /forgot-password             – validate identifier, then call
 *                                      `hooks.onForgotPasswordRequested`
 *                                      (use this to queue the reset email).
 *                                      Always returns the same neutral message
 *                                      to prevent user enumeration.
 *   GET  /reset-password/:selector    – validate selector + token from query string
 *   POST /reset-password              – validate selector + token, update password
 *
 * Required models: User, ForgotPassword
 * Required hook:   hooks.onForgotPasswordRequested  (to send the email)
 */
export function registerForgottenPasswordStrategy(
	app: FastifyInstance,
	opts: AuthFastifyPluginOptions,
): void {
	const { auth, models, hooks } = opts;
	const { User, ForgotPassword } = models;

	if (!ForgotPassword) {
		throw new Error(
			"ForgotPassword model is required for the 'forgotten-password' strategy",
		);
	}

	// ── POST /forgot-password ─────────────────────────────────────────────────

	app.post(
		"/forgot-password",
		async (request: FastifyRequest, reply: FastifyReply) => {
			const { identifier } = request.body as { identifier?: string };

			if (!identifier || !IDENTIFIER_RE.test(identifier)) {
				return reply.status(400).send({ error: "Invalid identifier" });
			}

			const normalizedIdentifier = auth.normalize(identifier);
			const isEmailAddress = isEmail(normalizedIdentifier);

			if (hooks?.onForgotPasswordRequested) {
				await hooks.onForgotPasswordRequested({
					identifier: normalizedIdentifier,
					isEmail: isEmailAddress,
				});
			}

			// Always return the same response to avoid leaking whether the account exists.
			return reply.send({
				message:
					"If an account with that username/email exists, we've sent password reset instructions.",
			});
		},
	);

	// ── GET /reset-password/:selector ────────────────────────────────────────

	app.get(
		"/reset-password/:selector",
		async (request: FastifyRequest, reply: FastifyReply) => {
			const { selector } = request.params as { selector: string };
			const { token } = request.query as { token?: string };

			if (!token || !selector) {
				return reply
					.status(400)
					.send({ error: "Invalid reset password selector or token" });
			}

			const result = await validateResetToken({
				ForgotPassword,
				auth,
				selector,
				token,
			});
			if (!result.valid) {
				return reply.status(400).send({ error: result.error });
			}

			return reply.send({ message: "Password reset token is valid" });
		},
	);

	// ── POST /reset-password ──────────────────────────────────────────────────

	app.post(
		"/reset-password",
		async (request: FastifyRequest, reply: FastifyReply) => {
			const { selector, token, password, password_confirmation } =
				request.body as {
					selector: string;
					token: string;
					password: string;
					password_confirmation: string;
				};

			if (!password || !password_confirmation) {
				return reply.status(400).send({
					error: "Password and password confirmation are required",
				});
			}
			if (password !== password_confirmation) {
				return reply.status(400).send({
					error: "Password and password confirmation do not match",
				});
			}
			if (!auth.validatePassword(password)) {
				return reply
					.status(400)
					.send({ error: "Password does not meet validation rules" });
			}

			if (!token || !selector) {
				return reply
					.status(400)
					.send({ error: "Invalid reset password selector or token" });
			}

			const result = await validateResetToken({
				ForgotPassword,
				auth,
				selector,
				token,
			});
			if (!result.valid) {
				return reply.status(400).send({ error: result.error });
			}

			const user = await User.query().findById(result.record.user_id);
			if (!user) {
				return reply.status(400).send({
					error: "User not found for this password reset request",
				});
			}

			await user.updatePassword(password);
			await result.record.markAsUsed();

			return reply.send({ message: "Password reset successfully" });
		},
	);
}
