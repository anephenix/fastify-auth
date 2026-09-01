// Dependencies
import type { Auth } from "@anephenix/auth";
import type { FastifyReply, FastifyRequest } from "fastify";
import { detectClientType } from "../helpers/detect-client-type.js";
import type { ISessionModelStatic } from "../types.js";

export type SessionTokens = {
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
};

/*
  Creates a Session record for the given user and returns just the token
  fields (never the full ORM row) - the shared step every strategy that
  ends in a logged-in session (sessions, magic-links, mfa-sms, mfa-totp)
  performs identically.
*/
export async function createSession(
	Session: ISessionModelStatic,
	userId: string | number,
): Promise<SessionTokens> {
	const session = await Session.query().insert({
		user_id: userId,
		...Session.generateTokens(),
	});
	const {
		access_token,
		refresh_token,
		access_token_expires_at,
		refresh_token_expires_at,
	} = session;
	return {
		access_token,
		refresh_token,
		access_token_expires_at,
		refresh_token_expires_at,
	};
}

function setAccessTokenCookie(
	reply: FastifyReply,
	auth: Auth,
	secureCookie: boolean,
	access_token: string,
) {
	return reply.setCookie("access_token", access_token, {
		httpOnly: true,
		secure: secureCookie,
		sameSite: "strict",
		path: "/",
		maxAge: auth.accessTokenExpiresIn,
	});
}

type RespondWithSessionParams = {
	request: FastifyRequest;
	reply: FastifyReply;
	auth: Auth;
	secureCookie: boolean;
	tokens: SessionTokens;
};

/*
  Responds to a request that just produced a brand new session - sets both
  access/refresh cookies for web clients, or returns the full token set in
  the JSON body for API clients. Used after password login, magic-link
  verification, SMS code verification, and MFA verification.
*/
export function respondWithNewSession({
	request,
	reply,
	auth,
	secureCookie,
	tokens,
}: RespondWithSessionParams) {
	const clientType = detectClientType(request);
	if (clientType === "web") {
		return setAccessTokenCookie(reply, auth, secureCookie, tokens.access_token)
			.status(201)
			.setCookie("refresh_token", tokens.refresh_token, {
				httpOnly: true,
				secure: secureCookie,
				sameSite: "strict",
				path: "/auth/refresh",
				maxAge: auth.refreshTokenExpiresIn,
			})
			.send("Authenticated successfully");
	}

	return reply.status(201).send(tokens);
}

/*
  Responds to a request that refreshed an existing session's access token -
  only the access_token cookie is reset for web clients (the refresh token
  is unchanged), or the full token set is returned in the JSON body for API
  clients. Used by POST /auth/refresh.
*/
export function respondWithRefreshedSession({
	request,
	reply,
	auth,
	secureCookie,
	tokens,
}: RespondWithSessionParams) {
	const clientType = detectClientType(request);
	if (clientType === "web") {
		return setAccessTokenCookie(reply, auth, secureCookie, tokens.access_token)
			.status(201)
			.send("Token refreshed successfully");
	}

	return reply.status(201).send(tokens);
}
