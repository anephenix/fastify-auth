import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createSession } from "../core/session.js";
import { handleError } from "../helpers/handle-error.js";
import type { AuthFastifyPluginOptions } from "../types.js";

/* Checks whether a string is the correct format for an email address */
const isEmail = (value: string): boolean =>
	/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

/**
 * Registers the magic-link (passwordless email) route set:
 *
 *   POST /magic-links         – look up user by email, create a magic-link
 *                               record, then call `hooks.onMagicLinkCreated`
 *                               (use this hook to send the email).
 *   POST /magic-links/verify  – verify token + code, create a session and
 *                               return access / refresh tokens.
 *
 * Required models: User, Session, MagicLink
 * Required hook:   hooks.onMagicLinkCreated  (to deliver the email)
 */
export function registerMagicLinksStrategy(
	app: FastifyInstance,
	opts: AuthFastifyPluginOptions,
): void {
	const { models, hooks } = opts;
	const { User, Session, MagicLink } = models;

	if (!Session) {
		throw new Error("Session model is required for the 'magic-links' strategy");
	}
	if (!MagicLink) {
		throw new Error(
			"MagicLink model is required for the 'magic-links' strategy",
		);
	}

	// ── POST /magic-links ─────────────────────────────────────────────────────

	app.post(
		"/magic-links",
		async (request: FastifyRequest, reply: FastifyReply) => {
			try {
				const { email } = request.body as { email?: string };

				if (!email) {
					throw new Error("No email provided - please provide an email");
				}
				if (!isEmail(email)) {
					throw new Error("Invalid email address");
				}

				const user = await User.query().where({ email }).first();
				if (!user) {
					throw new Error("User not found for email");
				}

				const { token, tokenExpiresAt, code, hashedCode } =
					await MagicLink.generateTokens();

				await MagicLink.query().insert({
					user_id: user.id,
					token,
					hashed_code: hashedCode,
					expires_at: tokenExpiresAt.toISOString(),
				});

				if (hooks?.onMagicLinkCreated) {
					await hooks.onMagicLinkCreated({ user, token, code, tokenExpiresAt });
				}

				reply.code(201).send({ message: "Magic link created" });
			} catch (err) {
				reply.status(400).send({ error: handleError(err as Error) });
			}
		},
	);

	// ── POST /magic-links/verify ──────────────────────────────────────────────

	app.post(
		"/magic-links/verify",
		async (request: FastifyRequest, reply: FastifyReply) => {
			try {
				const { token, code } = request.body as {
					token?: string;
					code?: string;
				};

				if (!token || !code) {
					throw new Error("Token and code are required");
				}

				const { userId } = await MagicLink.verifyTokenAndCode(token, code);

				const tokens = await createSession(Session, userId);
				reply.code(201).send(tokens);
			} catch (err) {
				reply.status(400).send({ error: handleError(err as Error) });
			}
		},
	);
}
