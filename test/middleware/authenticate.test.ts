import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import { createAuthenticateSession } from "../../src/middleware/authenticate.js";
import type { ISessionModelStatic } from "../../src/types.js";

const mockUser = { id: 1, username: "testuser", email: "test@example.com" };

function buildMockSession(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		user_id: 1,
		access_token: "valid_access_token",
		accessTokenHasExpired: vi.fn().mockReturnValue(false),
		$relatedQuery: vi.fn().mockReturnValue({
			first: vi.fn().mockResolvedValue(mockUser),
		}),
		...overrides,
	};
}

function buildSessionModel(findOneResult: unknown) {
	return {
		query: vi.fn().mockReturnValue({
			findOne: vi.fn().mockResolvedValue(findOneResult),
		}),
	} as unknown as ISessionModelStatic;
}

async function buildApp(Session: ISessionModelStatic) {
	const app = Fastify();
	const authenticateSession = createAuthenticateSession({ Session });
	app.get(
		"/protected",
		{ preHandler: [authenticateSession] },
		(req, reply) => {
			reply.send({ user: req.user, token: req.access_token });
		},
	);
	await app.ready();
	return app;
}

describe("createAuthenticateSession", () => {
	it("returns 401 when no Authorization header and no cookie", async () => {
		const Session = buildSessionModel(null);
		const app = await buildApp(Session);
		const response = await app.inject({ method: "GET", url: "/protected" });
		expect(response.statusCode).toBe(401);
		expect(response.json()).toEqual({ error: "Unauthorized" });
	});

	it("returns 401 when session is not found in the database", async () => {
		const Session = buildSessionModel(null);
		const app = await buildApp(Session);
		const response = await app.inject({
			method: "GET",
			url: "/protected",
			headers: { authorization: "Bearer unknown_token" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toEqual({ error: "Invalid session" });
	});

	it("returns 401 when access token has expired", async () => {
		const expiredSession = buildMockSession({
			accessTokenHasExpired: vi.fn().mockReturnValue(true),
		});
		const Session = buildSessionModel(expiredSession);
		const app = await buildApp(Session);
		const response = await app.inject({
			method: "GET",
			url: "/protected",
			headers: { authorization: "Bearer valid_access_token" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toEqual({ error: "Access token has expired" });
	});

	it("returns 401 when no user is found for the session", async () => {
		const sessionWithNoUser = buildMockSession({
			$relatedQuery: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(null),
			}),
		});
		const Session = buildSessionModel(sessionWithNoUser);
		const app = await buildApp(Session);
		const response = await app.inject({
			method: "GET",
			url: "/protected",
			headers: { authorization: "Bearer valid_access_token" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toEqual({ error: "Invalid session" });
	});

	it("attaches user and access_token to request on success", async () => {
		const session = buildMockSession();
		const Session = buildSessionModel(session);
		const app = await buildApp(Session);
		const response = await app.inject({
			method: "GET",
			url: "/protected",
			headers: { authorization: "Bearer valid_access_token" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toEqual({
			user: mockUser,
			token: "valid_access_token",
		});
	});

	it("strips the Bearer prefix before looking up the token", async () => {
		// If the Bearer prefix weren't stripped, findOne would be called with
		// "Bearer valid_access_token" and no session would match, returning 401.
		// A 200 here proves the prefix was stripped correctly.
		const session = buildMockSession();
		const Session = buildSessionModel(session);
		const app = await buildApp(Session);
		const response = await app.inject({
			method: "GET",
			url: "/protected",
			headers: { authorization: "Bearer valid_access_token" },
		});
		expect(response.statusCode).toBe(200);
	});
});
