import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { handleError } from "../helpers/handle-error.js";
import type { AuthFastifyPluginOptions } from "../types.js";

/**
 * Registers the SMS-based multi-factor authentication route set:
 *
 *   POST /sessions             – authenticate with username/password; on success
 *                               generate an SMS code, persist it, call
 *                               `hooks.onSmsCodeCreated` (use this to send the
 *                               SMS), and return the lookup `token`.
 *   POST /sessions/verify-code – verify the token + SMS code, create a session
 *                               and return access / refresh tokens.
 *
 * Required models: User, Session, SmsCode
 * Required hook:   hooks.onSmsCodeCreated  (to deliver the SMS)
 */
export function registerMfaSmsStrategy(
	app: FastifyInstance,
	opts: AuthFastifyPluginOptions,
): void {
	const { auth, models, hooks } = opts;
	const { User, Session, SmsCode } = models;

	if (!Session) {
		throw new Error("Session model is required for the 'mfa-sms' strategy");
	}
	if (!SmsCode) {
		throw new Error("SmsCode model is required for the 'mfa-sms' strategy");
	}

	// ── POST /sessions ────────────────────────────────────────────────────────

	app.post(
		"/sessions",
		async (request: FastifyRequest, reply: FastifyReply) => {
			try {
				const { identifier, password } = request.body as {
					identifier: string;
					password: string;
				};

				if (!identifier) {
					throw new Error("Please provide your username or email address");
				}
				if (!password) throw new Error("Password is required");

				const user = await User.authenticate({ identifier, password });
				if (!user) {
					return reply.status(401).send({ error: "Invalid credentials" });
				}

				const { token, code, hashedCode, expiresAt } =
					await auth.generateSmsCode();

				await SmsCode.query().insert({
					user_id: user.id,
					token,
					hashed_code: hashedCode,
					expires_at: expiresAt.toISOString(),
				});

				if (hooks?.onSmsCodeCreated) {
					await hooks.onSmsCodeCreated({ user, token, code });
				}

				return reply.status(201).send({
					token,
					message:
						"Authentication successful. SMS code sent to verify authentication",
				});
			} catch (error) {
				reply.status(401).send({ error: handleError(error as Error) });
			}
		},
	);

	// ── POST /sessions/verify-code ────────────────────────────────────────────

	app.post(
		"/sessions/verify-code",
		async (request: FastifyRequest, reply: FastifyReply) => {
			try {
				const { token, code } = request.body as { token: string; code: string };

				if (!token) {
					return reply.status(400).send({ error: "Token is required" });
				}
				if (!code) {
					return reply.status(400).send({ error: "Code is required" });
				}

				/*
          NOTE - do we need to perform any validation checks on the token/code,
          or do we trust the ORM to perform injection attack prevention?
        */

				const smsCode = await SmsCode.query().findOne({ token });
				if (!smsCode) {
					return reply.status(400).send({ error: "Invalid token" });
				}
				if (smsCode.used_at) {
					return reply
						.status(400)
						.send({ error: "Code has already been used" });
				}
				if (smsCode.codeHasExpired()) {
					return reply.status(400).send({ error: "Code has expired" });
				}

				const isCodeValid = await smsCode.verifyCode(code);
				if (!isCodeValid) {
					return reply.status(400).send({ error: "Invalid code" });
				}

				await smsCode.$query().patch({ used_at: new Date().toISOString() });

				const session = await Session.query().insert({
					user_id: smsCode.user_id,
					...Session.generateTokens(),
				});

				const {
					access_token,
					refresh_token,
					access_token_expires_at,
					refresh_token_expires_at,
				} = session;

				return reply.status(201).send({
					access_token,
					refresh_token,
					access_token_expires_at,
					refresh_token_expires_at,
				});
			} catch (error) {
				reply.status(401).send({ error: handleError(error as Error) });
			}
		},
	);
}
