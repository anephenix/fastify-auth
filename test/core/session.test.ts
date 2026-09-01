import type { Auth } from "@anephenix/auth";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { describe, expect, it, vi } from "vitest";
import {
	createSession,
	respondWithNewSession,
	respondWithRefreshedSession,
} from "../../src/core/session.js";
import type { ISessionModelStatic } from "../../src/types.js";

const tokenObj = {
	access_token: "test_access_token",
	access_token_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
	refresh_token: "test_refresh_token",
	refresh_token_expires_at: new Date(Date.now() + 86_400_000).toISOString(),
};

const mockAuth = {
	accessTokenExpiresIn: 3600,
	refreshTokenExpiresIn: 86400,
} as unknown as Auth;

describe("createSession", () => {
	it("inserts a session and returns only the token fields", async () => {
		const insert = vi
			.fn()
			.mockResolvedValue({ id: 1, user_id: 42, ...tokenObj });
		const Session = {
			query: vi.fn().mockReturnValue({ insert }),
			generateTokens: vi.fn().mockReturnValue(tokenObj),
		} as unknown as ISessionModelStatic;

		const tokens = await createSession(Session, 42);

		expect(insert).toHaveBeenCalledWith({ user_id: 42, ...tokenObj });
		expect(tokens).toEqual(tokenObj);
		expect(tokens).not.toHaveProperty("id");
		expect(tokens).not.toHaveProperty("user_id");
	});
});

function buildApp() {
	const app = Fastify();
	app.register(cookie);
	app.post(
		"/new-session",
		async (request: FastifyRequest, reply: FastifyReply) =>
			respondWithNewSession({
				request,
				reply,
				auth: mockAuth,
				secureCookie: false,
				tokens: tokenObj,
			}),
	);
	app.post(
		"/refreshed-session",
		async (request: FastifyRequest, reply: FastifyReply) =>
			respondWithRefreshedSession({
				request,
				reply,
				auth: mockAuth,
				secureCookie: false,
				tokens: tokenObj,
			}),
	);
	return app;
}

describe("respondWithNewSession", () => {
	it("returns the token set as JSON for API clients", async () => {
		const app = buildApp();
		await app.ready();
		const response = await app.inject({ method: "POST", url: "/new-session" });
		expect(response.statusCode).toBe(201);
		expect(response.json()).toEqual(tokenObj);
	});

	it("sets access_token and refresh_token cookies and a plain-text body for web clients", async () => {
		const app = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/new-session",
			headers: { "x-client-type": "web" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.body).toBe("Authenticated successfully");
		expect(response.cookies.map((c) => c.name).sort()).toEqual([
			"access_token",
			"refresh_token",
		]);
	});
});

describe("respondWithRefreshedSession", () => {
	it("returns the token set as JSON for API clients", async () => {
		const app = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/refreshed-session",
		});
		expect(response.statusCode).toBe(201);
		expect(response.json()).toEqual(tokenObj);
	});

	it("sets only the access_token cookie and a plain-text body for web clients", async () => {
		const app = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/refreshed-session",
			headers: { "x-client-type": "web" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.body).toBe("Token refreshed successfully");
		expect(response.cookies.map((c) => c.name)).toEqual(["access_token"]);
	});
});
