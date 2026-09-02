import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { verifyPassword } from "../core/password.js";
import { createSession, respondWithNewSession } from "../core/session.js";
import {
	createDeleteAllSessionsHandler,
	createDeleteSessionHandler,
	createListSessionsHandler,
	createLogoutHandler,
	createProfileHandler,
	createRefreshHandler,
} from "../core/session-management.js";
import { handleError } from "../helpers/handle-error.js";
import { createAuthenticateSession } from "../middleware/authenticate.js";
import type { AuthFastifyPluginOptions } from "../types.js";

/**
 * Registers the full session-based auth route set:
 *
 *   POST   /signup              – create a user account
 *   POST   /login               – authenticate and receive tokens / cookies
 *   GET    /profile             – (protected) return the current user
 *   POST   /logout              – (protected) delete the current session
 *   POST   /auth/refresh        – exchange a refresh token for a new access token
 *   GET    /sessions            – (protected) list all sessions for the user
 *   DELETE /sessions            – (protected) delete all sessions except the current one
 *   DELETE /sessions/:id        – (protected) delete a specific session
 *
 * Web clients (detected via `x-client-type: web` or `Accept: text/html`) receive
 * tokens as HttpOnly cookies. API clients receive them in the JSON response body.
 */
export function registerSessionsStrategy(
	app: FastifyInstance,
	opts: AuthFastifyPluginOptions,
): void {
	const { auth, models } = opts;
	const { User, Session } = models;

	if (!Session) {
		throw new Error("Session model is required for the 'sessions' strategy");
	}

	const secureCookie =
		opts.secureCookie ?? process.env.NODE_ENV === "production";
	const authenticateSession = createAuthenticateSession({ Session });

	// ── POST /signup ─────────────────────────────────────────────────────────

	app.post("/signup", async (request: FastifyRequest, reply: FastifyReply) => {
		const { username, email, password, mobile_number } = request.body as {
			username: string;
			email: string;
			password: string;
			// Optional - not needed for password login, but there if you want
			// to collect it (e.g. to add mfa-sms/mfa-totp for this user later).
			mobile_number?: string;
		};

		try {
			const user = await User.query().insert({
				username,
				email,
				password,
				...(mobile_number && { mobile_number }),
			});
			reply
				.status(201)
				.send({ id: user.id, username: user.username, email: user.email });
		} catch (error) {
			reply.status(400).send({ error: handleError(error as Error) });
		}
	});

	// ── POST /login ───────────────────────────────────────────────────────────

	app.post("/login", async (request: FastifyRequest, reply: FastifyReply) => {
		const { identifier, password } = request.body as {
			identifier: string;
			password: string;
		};

		try {
			const user = await verifyPassword(User, identifier, password);
			if (!user) {
				return reply.status(401).send({ error: "Invalid credentials" });
			}

			const tokens = await createSession(Session, user.id);
			return respondWithNewSession({
				request,
				reply,
				auth,
				secureCookie,
				tokens,
			});
		} catch (error) {
			reply.status(401).send({ error: handleError(error as Error) });
		}
	});

	// ── GET /profile (protected) ──────────────────────────────────────────────

	app.get(
		"/profile",
		{ preHandler: [authenticateSession] },
		createProfileHandler(),
	);

	// ── POST /logout (protected) ──────────────────────────────────────────────

	app.post(
		"/logout",
		{ preHandler: [authenticateSession] },
		createLogoutHandler(Session),
	);

	// ── POST /auth/refresh ────────────────────────────────────────────────────

	app.post(
		"/auth/refresh",
		createRefreshHandler({ Session, auth, secureCookie }),
	);

	// ── GET /sessions (protected) ─────────────────────────────────────────────

	app.get(
		"/sessions",
		{ preHandler: [authenticateSession] },
		createListSessionsHandler(Session),
	);

	// ── DELETE /sessions (protected) – delete all except active ──────────────

	app.delete(
		"/sessions",
		{ preHandler: [authenticateSession] },
		createDeleteAllSessionsHandler(Session),
	);

	// ── DELETE /sessions/:id (protected) ──────────────────────────────────────

	app.delete(
		"/sessions/:id",
		{ preHandler: [authenticateSession] },
		createDeleteSessionHandler(Session),
	);
}
