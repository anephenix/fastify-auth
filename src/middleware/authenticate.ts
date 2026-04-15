import type { FastifyReply, FastifyRequest } from "fastify";
import type { ISessionModelStatic } from "../types.js";

/**
 * Factory that returns a Fastify `preHandler` which:
 *  1. Extracts the access token from `Authorization: Bearer <token>` or the
 *     `access_token` cookie.
 *  2. Looks up the session in the database.
 *  3. Checks the token hasn't expired.
 *  4. Loads the related user via `session.$relatedQuery('user')`.
 *  5. Attaches `request.user` and `request.access_token` for downstream handlers.
 *
 * Returns 401 at the first failing step.
 */
export function createAuthenticateSession({
	Session,
}: {
	Session: ISessionModelStatic;
}) {
	return async function authenticateSession(
		request: FastifyRequest,
		reply: FastifyReply,
	): Promise<void> {
		const access_token =
			request.headers.authorization?.replace("Bearer ", "") ||
			request.cookies?.access_token;

		if (!access_token) {
			reply.code(401).send({ error: "Unauthorized" });
			return;
		}

		const session = await Session.query().findOne({ access_token });
		if (!session) {
			reply.code(401).send({ error: "Invalid session" });
			return;
		}

		if (session.accessTokenHasExpired()) {
			reply.code(401).send({ error: "Access token has expired" });
			return;
		}

		const user = await session.$relatedQuery("user").first();
		if (!user) {
			reply.code(401).send({ error: "Invalid session" });
			return;
		}

		request.access_token = session.access_token;
		request.user = user;
	};
}
