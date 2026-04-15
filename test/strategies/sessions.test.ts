import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import { registerSessionsStrategy } from "../../src/strategies/sessions.js";
import type {
	AuthFastifyPluginOptions,
	ISessionModelStatic,
	IUserModelStatic,
} from "../../src/types.js";

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const mockUser = { id: 1, username: "testuser", email: "test@example.com" };

const tokenObj = {
	access_token: "test_access_token",
	access_token_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
	refresh_token: "test_refresh_token",
	refresh_token_expires_at: new Date(Date.now() + 86_400_000).toISOString(),
};

function buildMockSession(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		user_id: 1,
		...tokenObj,
		accessTokenHasExpired: vi.fn().mockReturnValue(false),
		refreshTokenHasExpired: vi.fn().mockReturnValue(false),
		$relatedQuery: vi.fn().mockReturnValue({
			first: vi.fn().mockResolvedValue(mockUser),
		}),
		$query: vi.fn().mockReturnValue({
			delete: vi.fn().mockResolvedValue(1),
			patchAndFetch: vi.fn().mockResolvedValue({ ...tokenObj, id: 1 }),
			patch: vi.fn().mockResolvedValue(1),
		}),
		...overrides,
	};
}

const mockAuth = {
	accessTokenExpiresIn: 3600,
	refreshTokenExpiresIn: 86400,
};

// ─── App builder ─────────────────────────────────────────────────────────────

type QBOverrides = Record<string, unknown>;

function buildApp(queryOverrides: QBOverrides = {}, sessionObj = buildMockSession()) {
	const app = Fastify();
	app.register(cookie);

	// Base QB handles auth (findOne) and common operations; tests can override.
	const qb = {
		findOne: vi.fn().mockResolvedValue(sessionObj),
		insert: vi.fn().mockResolvedValue(sessionObj),
		select: vi.fn().mockReturnValue({
			where: vi.fn().mockResolvedValue([sessionObj]),
		}),
		delete: vi.fn().mockReturnValue({
			where: vi.fn().mockReturnValue({
				whereNot: vi.fn().mockResolvedValue(1),
			}),
		}),
		where: vi.fn().mockReturnValue({
			first: vi.fn().mockResolvedValue(sessionObj),
		}),
		...queryOverrides,
	};

	const Session = {
		query: vi.fn().mockReturnValue(qb),
		generateTokens: vi.fn().mockReturnValue(tokenObj),
	} as unknown as ISessionModelStatic;

	const User = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue(mockUser),
		}),
		authenticate: vi.fn().mockResolvedValue(mockUser),
	} as unknown as IUserModelStatic;

	const opts: AuthFastifyPluginOptions = {
		strategy: "sessions",
		auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
		models: { User, Session },
	};

	registerSessionsStrategy(app, opts);
	return { app, User, Session, qb };
}

// ─── POST /signup ─────────────────────────────────────────────────────────────

describe("POST /signup", () => {
	it("creates a user and returns 201", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/signup",
			payload: { username: "testuser", email: "test@example.com", password: "secret" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.json()).toMatchObject({ id: 1, username: "testuser", email: "test@example.com" });
	});

	it("returns 400 when user creation fails", async () => {
		const { app, User } = buildApp();
		(User.query as ReturnType<typeof vi.fn>).mockReturnValue({
			insert: vi.fn().mockRejectedValue(new Error("Database error")),
		});
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/signup",
			payload: { username: "testuser", email: "test@example.com", password: "secret" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Database error" });
	});

	it("returns a friendly message for duplicate email (UniqueViolationError)", async () => {
		const { app, User } = buildApp();
		const uniqueError = Object.assign(new Error("unique violation"), {
			columns: ["email"],
		});
		Object.defineProperty(uniqueError, "constructor", {
			value: { name: "UniqueViolationError" },
		});
		(User.query as ReturnType<typeof vi.fn>).mockReturnValue({
			insert: vi.fn().mockRejectedValue(uniqueError),
		});
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/signup",
			payload: { username: "testuser", email: "test@example.com", password: "secret" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "email already exists." });
	});
});

// ─── POST /login ──────────────────────────────────────────────────────────────

describe("POST /login", () => {
	it("returns 401 when identifier is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { password: "secret" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json().error).toMatch(/username or email/);
	});

	it("returns 401 when password is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json().error).toMatch(/Password/);
	});

	it("returns 401 when credentials are invalid", async () => {
		const { app, User } = buildApp();
		(User.authenticate as ReturnType<typeof vi.fn>).mockResolvedValue(null);
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser", password: "wrong" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toMatchObject({ error: "Invalid credentials" });
	});

	it("returns 201 with tokens for API clients", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser", password: "secret" },
			headers: { accept: "application/json" },
		});
		expect(response.statusCode).toBe(201);
		const body = response.json();
		expect(body).toHaveProperty("access_token");
		expect(body).toHaveProperty("refresh_token");
		expect(body).toHaveProperty("access_token_expires_at");
		expect(body).toHaveProperty("refresh_token_expires_at");
	});

	it("returns 201 and sets cookies for web clients", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser", password: "secret" },
			headers: { "x-client-type": "web" },
		});
		expect(response.statusCode).toBe(201);
		const setCookieHeader = response.headers["set-cookie"];
		expect(Array.isArray(setCookieHeader) || typeof setCookieHeader === "string").toBe(true);
		const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
		expect(cookies.some((c: string) => c.startsWith("access_token="))).toBe(true);
		expect(cookies.some((c: string) => c.startsWith("refresh_token="))).toBe(true);
	});
});

// ─── GET /profile ─────────────────────────────────────────────────────────────

describe("GET /profile", () => {
	it("returns 401 when not authenticated", async () => {
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(null) });
		await app.ready();
		const response = await app.inject({ method: "GET", url: "/profile" });
		expect(response.statusCode).toBe(401);
	});

	it("returns user data for authenticated requests", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/profile",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toMatchObject({ id: 1, username: "testuser", email: "test@example.com" });
	});
});

// ─── POST /logout ─────────────────────────────────────────────────────────────

describe("POST /logout", () => {
	it("returns 401 when not authenticated", async () => {
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(null) });
		await app.ready();
		const response = await app.inject({ method: "POST", url: "/logout" });
		expect(response.statusCode).toBe(401);
	});

	it("deletes the session and returns 200 for authenticated requests", async () => {
		const deleteWhere = vi.fn().mockResolvedValue(1);
		const deleteQB = { where: deleteWhere };
		const { app } = buildApp({ delete: vi.fn().mockReturnValue(deleteQB) });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/logout",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toMatchObject({ message: "Logged out successfully" });
	});
});

// ─── POST /auth/refresh ───────────────────────────────────────────────────────

describe("POST /auth/refresh", () => {
	it("returns 401 when no refresh token is provided", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/refresh",
			payload: {},
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toMatchObject({ error: "No refresh token provided" });
	});

	it("returns 401 for invalid or expired refresh token", async () => {
		const expiredSession = buildMockSession({
			refreshTokenHasExpired: vi.fn().mockReturnValue(true),
		});
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(expiredSession) });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/refresh",
			payload: { refresh_token: "expired_token" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json().error).toMatch(/expired/);
	});

	it("returns 401 when the session is not found", async () => {
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(null) });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/refresh",
			payload: { refresh_token: "unknown_token" },
		});
		expect(response.statusCode).toBe(401);
	});

	it("returns 201 with new tokens for API clients", async () => {
		const updatedSession = { ...tokenObj, id: 1 };
		const session = buildMockSession();
		(session.$query as ReturnType<typeof vi.fn>).mockReturnValue({
			patchAndFetch: vi.fn().mockResolvedValue(updatedSession),
		});
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(session) });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/refresh",
			payload: { refresh_token: "test_refresh_token" },
			headers: { accept: "application/json" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.json()).toHaveProperty("access_token");
	});

	it("sets a new access_token cookie for web clients on refresh", async () => {
		const updatedSession = { ...tokenObj, id: 1 };
		const session = buildMockSession();
		(session.$query as ReturnType<typeof vi.fn>).mockReturnValue({
			patchAndFetch: vi.fn().mockResolvedValue(updatedSession),
		});
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(session) });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/refresh",
			payload: { refresh_token: "test_refresh_token" },
			headers: { "x-client-type": "web" },
		});
		expect(response.statusCode).toBe(201);
		const setCookieHeader = response.headers["set-cookie"];
		const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
		expect(cookies.some((c: string) => c.startsWith("access_token="))).toBe(true);
	});
});

// ─── GET /sessions ────────────────────────────────────────────────────────────

describe("GET /sessions", () => {
	it("returns 401 when not authenticated", async () => {
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(null) });
		await app.ready();
		const response = await app.inject({ method: "GET", url: "/sessions" });
		expect(response.statusCode).toBe(401);
	});

	it("returns the list of sessions for authenticated requests", async () => {
		const sessionList = [{ id: 1 }, { id: 2 }];
		const selectQB = { where: vi.fn().mockResolvedValue(sessionList) };
		const { app } = buildApp({ select: vi.fn().mockReturnValue(selectQB) });
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/sessions",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(200);
		expect(Array.isArray(response.json())).toBe(true);
	});
});

// ─── DELETE /sessions ─────────────────────────────────────────────────────────

describe("DELETE /sessions", () => {
	it("returns 401 when not authenticated", async () => {
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(null) });
		await app.ready();
		const response = await app.inject({ method: "DELETE", url: "/sessions" });
		expect(response.statusCode).toBe(401);
	});

	it("deletes all other sessions and returns 200", async () => {
		const whereNotQB = { whereNot: vi.fn().mockResolvedValue(1) };
		const whereQB = { where: vi.fn().mockReturnValue(whereNotQB) };
		const { app } = buildApp({ delete: vi.fn().mockReturnValue(whereQB) });
		await app.ready();
		const response = await app.inject({
			method: "DELETE",
			url: "/sessions",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toMatchObject({ message: "Sessions deleted successfully" });
	});
});

// ─── DELETE /sessions/:id ─────────────────────────────────────────────────────

describe("DELETE /sessions/:id", () => {
	it("returns 401 when not authenticated", async () => {
		const { app } = buildApp({ findOne: vi.fn().mockResolvedValue(null) });
		await app.ready();
		const response = await app.inject({ method: "DELETE", url: "/sessions/99" });
		expect(response.statusCode).toBe(401);
	});

	it("returns 404 when session not found", async () => {
		// findOne is used for auth (returns session), where().first() for session lookup (returns null)
		const authSession = buildMockSession();
		const qb: QBOverrides = {
			findOne: vi.fn().mockResolvedValue(authSession),
			where: vi.fn().mockReturnValue({ first: vi.fn().mockResolvedValue(null) }),
		};
		const { app } = buildApp(qb);
		await app.ready();
		const response = await app.inject({
			method: "DELETE",
			url: "/sessions/99",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(404);
		expect(response.json()).toMatchObject({ error: "Session not found" });
	});

	it("returns 409 when trying to delete the active session", async () => {
		const session = buildMockSession({ access_token: "test_access_token" });
		const { app } = buildApp({
			findOne: vi.fn().mockResolvedValue(session),
			where: vi.fn().mockReturnValue({ first: vi.fn().mockResolvedValue(session) }),
		});
		await app.ready();
		const response = await app.inject({
			method: "DELETE",
			url: "/sessions/1",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(409);
		expect(response.json().error).toBe("conflict");
	});

	it("deletes a specific session and returns 200 for API clients", async () => {
		const authSession = buildMockSession({ access_token: "test_access_token" });
		const targetSession = buildMockSession({
			id: 2,
			access_token: "other_token",
			$query: vi.fn().mockReturnValue({ delete: vi.fn().mockResolvedValue(1) }),
		});
		const { app } = buildApp({
			findOne: vi.fn().mockResolvedValue(authSession),
			where: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(targetSession),
			}),
		});
		await app.ready();
		const response = await app.inject({
			method: "DELETE",
			url: "/sessions/2",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(200);
	});
});

// ─── Strategy registration ────────────────────────────────────────────────────

describe("registerSessionsStrategy", () => {
	it("throws when Session model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		expect(() =>
			registerSessionsStrategy(app, {
				strategy: "sessions",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User },
			}),
		).toThrow("Session model is required");
	});
});
