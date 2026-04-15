import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { detectClientType } from "../helpers/detect-client-type.js";
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
		const { username, email, password } = request.body as {
			username: string;
			email: string;
			password: string;
		};

		try {
			const user = await User.query().insert({ username, email, password });
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
			if (!identifier) {
				throw new Error("Please provide your username or email address");
			}
			if (!password) throw new Error("Password is required");

			const user = await User.authenticate({ identifier, password });
			if (!user) {
				return reply.status(401).send({ error: "Invalid credentials" });
			}

			const session = await Session.query().insert({
				user_id: user.id,
				...Session.generateTokens(),
			});

			const {
				access_token,
				refresh_token,
				access_token_expires_at,
				refresh_token_expires_at,
			} = session;

			const clientType = detectClientType(request);
			if (clientType === "web") {
				return reply
					.status(201)
					.setCookie("access_token", access_token, {
						httpOnly: true,
						secure: secureCookie,
						sameSite: "strict",
						path: "/",
						maxAge: auth.accessTokenExpiresIn,
					})
					.setCookie("refresh_token", refresh_token, {
						httpOnly: true,
						secure: secureCookie,
						sameSite: "strict",
						path: "/auth/refresh",
						maxAge: auth.refreshTokenExpiresIn,
					})
					.send("Authenticated successfully");
			}

			return reply.status(201).send({
				access_token,
				refresh_token,
				access_token_expires_at,
				refresh_token_expires_at,
			});
		} catch (error) {
			reply.status(401).send({ error: handleError(error as Error) });
		}
	});

	// ── GET /profile (protected) ──────────────────────────────────────────────

	app.get(
		"/profile",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			if (!user) {
				return reply.status(401).send({ error: "Unauthorized" });
			}
			reply.send({ id: user.id, username: user.username, email: user.email });
		},
	);

	// ── POST /logout (protected) ──────────────────────────────────────────────

	app.post(
		"/logout",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			const access_token = request.access_token;
			if (!user) {
				return reply.status(401).send({ error: "Unauthorized" });
			}

			try {
				await Session.query()
					.delete()
					.where({ user_id: user.id, access_token });
				reply
					.clearCookie("access_token")
					.clearCookie("refresh_token")
					.send({ message: "Logged out successfully" });
			} catch (error) {
				reply.status(500).send({ error: handleError(error as Error) });
			}
		},
	);

	// ── POST /auth/refresh ────────────────────────────────────────────────────

	app.post(
		"/auth/refresh",
		async (request: FastifyRequest, reply: FastifyReply) => {
			const clientType = detectClientType(request);

			// Web clients send the refresh token as a cookie; API clients send it in the body.
			const refresh_token =
				request.cookies?.refresh_token ||
				(request.body as { refresh_token?: string })?.refresh_token;

			if (!refresh_token) {
				return reply.status(401).send({ error: "No refresh token provided" });
			}

			const session = await Session.query().findOne({ refresh_token });
			if (!session || session.refreshTokenHasExpired()) {
				const msg = "Invalid or expired refresh token";
				return reply
					.status(401)
					.send(clientType === "web" ? msg : { error: msg });
			}

			const updatedTokens = Session.generateTokens();
			const newSession = await session.$query().patchAndFetch({
				access_token: updatedTokens.access_token,
				access_token_expires_at: updatedTokens.access_token_expires_at,
			});

			if (clientType === "web") {
				return reply
					.setCookie("access_token", newSession.access_token, {
						httpOnly: true,
						secure: secureCookie,
						sameSite: "strict",
						path: "/",
						maxAge: auth.accessTokenExpiresIn,
					})
					.status(201)
					.send("Token refreshed successfully");
			}

			return reply.status(201).send({
				access_token: newSession.access_token,
				access_token_expires_at: newSession.access_token_expires_at,
				refresh_token: newSession.refresh_token,
				refresh_token_expires_at: newSession.refresh_token_expires_at,
			});
		},
	);

	// ── GET /sessions (protected) ─────────────────────────────────────────────

	app.get(
		"/sessions",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const sessions = await Session.query()
				.select("id", "user_agent", "ip_address", "created_at", "updated_at")
				.where("user_id", request.user.id);
			reply.status(200).send(sessions);
		},
	);

	// ── DELETE /sessions (protected) – delete all except active ──────────────

	app.delete(
		"/sessions",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			if (!user) {
				return reply.status(401).send({ error: "Unauthorized" });
			}

			try {
				await Session.query()
					.delete()
					.where({ user_id: user.id })
					.whereNot({ access_token: request.access_token });
				reply.status(200).send({ message: "Sessions deleted successfully" });
			} catch (error) {
				reply.status(500).send({ error: handleError(error as Error) });
			}
		},
	);

	// ── DELETE /sessions/:id (protected) ──────────────────────────────────────

	app.delete(
		"/sessions/:id",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const { id } = request.params as { id: string };
			const user = request.user;

			const session = await Session.query()
				.where({ id, user_id: user.id })
				.first();
			if (!session) {
				return reply.status(404).send({ error: "Session not found" });
			}

			if (session.access_token === request.access_token) {
				return reply.status(409).send({
					error: "conflict",
					message:
						"Cannot delete the active session. Use the /logout endpoint instead.",
				});
			}

			await session.$query().delete();
			const clientType = detectClientType(request);
			const message = "Session deleted successfully";
			reply.status(200).send(clientType === "web" ? message : { message });
		},
	);
}
