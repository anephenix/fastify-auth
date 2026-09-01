// Dependencies
import type { Auth } from "@anephenix/auth";
import type { FastifyReply, FastifyRequest } from "fastify";
import { detectClientType } from "../helpers/detect-client-type.js";
import { handleError } from "../helpers/handle-error.js";
import type { ISessionModelStatic } from "../types.js";
import { respondWithRefreshedSession } from "./session.js";

/*
  Route-handler factories for managing an existing session - profile,
  logout, token refresh, and listing/revoking sessions - independent of how
  that session was originally created (password login, magic link, SMS or
  TOTP MFA). Used by the 'sessions' strategy today; the point of pulling
  these out is that any future strategy combination that ends in a session
  can reuse the same management surface without depending on 'sessions'
  also owning '/signup'/'/login'.
*/

export function createProfileHandler() {
	return async (request: FastifyRequest, reply: FastifyReply) => {
		const user = request.user;
		if (!user) {
			return reply.status(401).send({ error: "Unauthorized" });
		}
		reply.send({ id: user.id, username: user.username, email: user.email });
	};
}

export function createLogoutHandler(Session: ISessionModelStatic) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
		const user = request.user;
		const access_token = request.access_token;
		if (!user) {
			return reply.status(401).send({ error: "Unauthorized" });
		}

		try {
			await Session.query().delete().where({ user_id: user.id, access_token });
			reply
				.clearCookie("access_token")
				.clearCookie("refresh_token")
				.send({ message: "Logged out successfully" });
		} catch (error) {
			reply.status(500).send({ error: handleError(error as Error) });
		}
	};
}

export function createRefreshHandler({
	Session,
	auth,
	secureCookie,
}: {
	Session: ISessionModelStatic;
	auth: Auth;
	secureCookie: boolean;
}) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
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

		return respondWithRefreshedSession({
			request,
			reply,
			auth,
			secureCookie,
			tokens: {
				access_token: newSession.access_token,
				access_token_expires_at: newSession.access_token_expires_at,
				refresh_token: newSession.refresh_token,
				refresh_token_expires_at: newSession.refresh_token_expires_at,
			},
		});
	};
}

export function createListSessionsHandler(Session: ISessionModelStatic) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
		const sessions = await Session.query()
			.select("id", "user_agent", "ip_address", "created_at", "updated_at")
			.where("user_id", request.user.id);
		reply.status(200).send(sessions);
	};
}

export function createDeleteAllSessionsHandler(Session: ISessionModelStatic) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
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
	};
}

export function createDeleteSessionHandler(Session: ISessionModelStatic) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
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
	};
}
