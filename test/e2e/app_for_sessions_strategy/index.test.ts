import { beforeEach, describe, expect, it } from "vitest";
import { type BuiltApp, buildApp } from "./index.js";

// ─── Test helpers ─────────────────────────────────────────────────────────────

const ALICE = {
	username: "alice",
	email: "alice@example.com",
	password: "secret123",
};

function asCookieArray(setCookie: string | string[] | undefined): string[] {
	if (!setCookie) return [];
	return Array.isArray(setCookie) ? setCookie : [setCookie];
}

function cookieValue(cookies: string[], name: string): string | undefined {
	const found = cookies.find((c) => c.startsWith(`${name}=`));
	return found?.split(";")[0]?.split("=")[1];
}

async function signup(ctx: BuiltApp, overrides: Partial<typeof ALICE> = {}) {
	return ctx.app.inject({
		method: "POST",
		url: "/signup",
		payload: { ...ALICE, ...overrides },
	});
}

async function login(
	ctx: BuiltApp,
	headers: Record<string, string> = {},
	overrides: { identifier?: string; password?: string } = {},
) {
	return ctx.app.inject({
		method: "POST",
		url: "/login",
		payload: {
			identifier: overrides.identifier ?? ALICE.username,
			password: overrides.password ?? ALICE.password,
		},
		headers,
	});
}

async function signupAndLoginAsApi(ctx: BuiltApp) {
	await signup(ctx);
	const response = await login(ctx);
	return response.json() as {
		access_token: string;
		refresh_token: string;
	};
}

describe("app_for_sessions_strategy", () => {
	let ctx: BuiltApp;

	beforeEach(async () => {
		ctx = buildApp();
		await ctx.app.ready();
	});

	describe("POST /signup", () => {
		describe("when an invalid user payload is provided", () => {
			it("should not create a user record in the database", async () => {
				await signup(ctx, { email: undefined, password: undefined });
				expect(ctx.users).toHaveLength(0);
			});

			it("should return a 400 HTTP status and a message of the error", async () => {
				const response = await signup(ctx, {
					email: undefined,
					password: undefined,
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when a valid user payload is provided", () => {
			it("should create a user record in the database", async () => {
				await signup(ctx);
				expect(ctx.users).toHaveLength(1);
				expect(ctx.users[0]).toMatchObject({
					username: ALICE.username,
					email: ALICE.email,
				});
			});

			it("should return a 201 HTTP status and the created user details", async () => {
				const response = await signup(ctx);
				expect(response.statusCode).toBe(201);
				expect(response.json()).toMatchObject({
					username: ALICE.username,
					email: ALICE.email,
				});
				expect(response.json()).toHaveProperty("id");
			});
		});

		describe("when mobile_number is provided", () => {
			it("should store it on the created user record (it's optional, not required)", async () => {
				await ctx.app.inject({
					method: "POST",
					url: "/signup",
					payload: { ...ALICE, mobile_number: "+15550001111" },
				});
				expect(ctx.users[0]).toMatchObject({ mobile_number: "+15550001111" });
			});
		});

		describe("when mobile_number is not provided", () => {
			it("should still create the user successfully", async () => {
				const response = await signup(ctx);
				expect(response.statusCode).toBe(201);
				expect(ctx.users[0].mobile_number).toBeUndefined();
			});
		});
	});

	describe("POST /login", () => {
		beforeEach(async () => {
			await signup(ctx);
		});

		describe("when no identifier is provided", () => {
			// NOTE: the current implementation returns 401 (not 400) here, since
			// the missing-identifier check throws into the same catch block that
			// handles invalid credentials. Matches the existing behavior asserted
			// in test/strategies/sessions.test.ts.
			it("should return a 401 HTTP status and a message asking to provide a username or email address", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login",
					payload: { password: ALICE.password },
				});
				expect(response.statusCode).toBe(401);
				expect(response.json().error).toMatch(/username or email/i);
			});
		});

		describe("when no password is provided", () => {
			it("should return a 401 HTTP status and a message asking to provide a password", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login",
					payload: { identifier: ALICE.username },
				});
				expect(response.statusCode).toBe(401);
				expect(response.json().error).toMatch(/password/i);
			});
		});

		describe("when the user authentication is invalid", () => {
			it("should return a 401 HTTP status and a message asking to provide valid credentials", async () => {
				const response = await login(ctx, {}, { password: "wrong-password" });
				expect(response.statusCode).toBe(401);
				expect(response.json()).toMatchObject({ error: "Invalid credentials" });
			});
		});

		describe("when the user authentication is valid", () => {
			it("should create a session record in the database for the user", async () => {
				await login(ctx);
				expect(ctx.sessions).toHaveLength(1);
				expect(ctx.sessions[0]).toMatchObject({ user_id: ctx.users[0].id });
			});

			describe("and when the clientType is web", () => {
				it("should set a cookie for the access_token", async () => {
					const response = await login(ctx, { "x-client-type": "web" });
					const cookies = asCookieArray(response.headers["set-cookie"]);
					expect(cookieValue(cookies, "access_token")).toBeTruthy();
				});

				it("should set a cookie for the refresh_token", async () => {
					const response = await login(ctx, { "x-client-type": "web" });
					const cookies = asCookieArray(response.headers["set-cookie"]);
					expect(cookieValue(cookies, "refresh_token")).toBeTruthy();
				});

				// NOTE: the current implementation returns 201 (not 200) on
				// successful login, matching POST /auth/refresh's convention of
				// 201 for a newly issued token.
				it("should return a 201 HTTP status saying Authenticated successfully", async () => {
					const response = await login(ctx, { "x-client-type": "web" });
					expect(response.statusCode).toBe(201);
					expect(response.body).toBe("Authenticated successfully");
				});
			});

			describe("and when the clientType is api", () => {
				it("should return a 201 HTTP status and the access and refresh tokens", async () => {
					const response = await login(ctx);
					expect(response.statusCode).toBe(201);
					const body = response.json();
					expect(body).toHaveProperty("access_token");
					expect(body).toHaveProperty("refresh_token");
					expect(body).toHaveProperty("access_token_expires_at");
					expect(body).toHaveProperty("refresh_token_expires_at");
				});
			});
		});
	});

	describe("GET /profile", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "GET",
					url: "/profile",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			it("should return the user details", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				const response = await ctx.app.inject({
					method: "GET",
					url: "/profile",
					headers: { authorization: `Bearer ${access_token}` },
				});
				expect(response.statusCode).toBe(200);
				expect(response.json()).toMatchObject({
					username: ALICE.username,
					email: ALICE.email,
				});
			});
		});
	});

	describe("POST /logout", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/logout",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			it("should delete the session record in the database for the user", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				expect(ctx.sessions).toHaveLength(1);
				await ctx.app.inject({
					method: "POST",
					url: "/logout",
					headers: { authorization: `Bearer ${access_token}` },
				});
				expect(ctx.sessions).toHaveLength(0);
			});

			it("should clear any cookies related to the session", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				const response = await ctx.app.inject({
					method: "POST",
					url: "/logout",
					headers: { authorization: `Bearer ${access_token}` },
				});
				const cookies = asCookieArray(response.headers["set-cookie"]);
				expect(cookies.some((c) => /^access_token=;/.test(c))).toBe(true);
				expect(cookies.some((c) => /^refresh_token=;/.test(c))).toBe(true);
			});

			it("should respond with a 200 and a message saying Logged out successfully", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				const response = await ctx.app.inject({
					method: "POST",
					url: "/logout",
					headers: { authorization: `Bearer ${access_token}` },
				});
				expect(response.statusCode).toBe(200);
				expect(response.json()).toMatchObject({
					message: "Logged out successfully",
				});
			});
		});
	});

	describe("POST /auth/refresh", () => {
		describe("when there is no refresh_token provided", () => {
			it("should respond with a HTTP status 401 and a message saying No refresh token provided", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/refresh",
					payload: {},
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toMatchObject({
					error: "No refresh token provided",
				});
			});
		});

		describe("when the refresh token has expired", () => {
			it("should respond with a HTTP status 401 and a message saying Invalid or expired refresh token", async () => {
				const { refresh_token } = await signupAndLoginAsApi(ctx);
				ctx.sessions[0].refresh_token_expires_at = new Date(
					Date.now() - 1000,
				).toISOString();
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/refresh",
					payload: { refresh_token },
				});
				expect(response.statusCode).toBe(401);
				expect(response.json().error).toMatch(/expired/i);
			});
		});

		describe("when the refresh token is valid", () => {
			it("should update the session with a new access token", async () => {
				const { refresh_token, access_token: originalAccessToken } =
					await signupAndLoginAsApi(ctx);
				await ctx.app.inject({
					method: "POST",
					url: "/auth/refresh",
					payload: { refresh_token },
				});
				expect(ctx.sessions[0].access_token).not.toBe(originalAccessToken);
			});

			describe("when the client type is web", () => {
				it("should set the access token cookie with the latest values", async () => {
					const loginResponse = await (async () => {
						await signup(ctx);
						return login(ctx, { "x-client-type": "web" });
					})();
					const loginCookies = asCookieArray(
						loginResponse.headers["set-cookie"],
					);
					const refresh_token = cookieValue(loginCookies, "refresh_token");

					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/refresh",
						headers: {
							"x-client-type": "web",
							cookie: `refresh_token=${refresh_token}`,
						},
					});

					const cookies = asCookieArray(response.headers["set-cookie"]);
					const newAccessToken = cookieValue(cookies, "access_token");
					expect(newAccessToken).toBeTruthy();
					expect(newAccessToken).toBe(ctx.sessions[0].access_token);
				});

				it("should respond with a 201 HTTP status and a message saying that the token was refreshed successfully", async () => {
					await signup(ctx);
					const loginResponse = await login(ctx, { "x-client-type": "web" });
					const loginCookies = asCookieArray(
						loginResponse.headers["set-cookie"],
					);
					const refresh_token = cookieValue(loginCookies, "refresh_token");

					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/refresh",
						headers: {
							"x-client-type": "web",
							cookie: `refresh_token=${refresh_token}`,
						},
					});

					expect(response.statusCode).toBe(201);
					expect(response.body).toBe("Token refreshed successfully");
				});
			});

			describe("when the client type is api", () => {
				it("should respond with a 201 HTTP status and the update access_token and refresh_token values", async () => {
					const { refresh_token } = await signupAndLoginAsApi(ctx);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/refresh",
						payload: { refresh_token },
					});
					expect(response.statusCode).toBe(201);
					const body = response.json();
					expect(body).toHaveProperty("access_token");
					expect(body).toHaveProperty("refresh_token");
					expect(body).toHaveProperty("access_token_expires_at");
					expect(body).toHaveProperty("refresh_token_expires_at");
				});
			});
		});
	});

	describe("GET /sessions", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "GET",
					url: "/sessions",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			it("should return the list of sessions for the logged-in user", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				const response = await ctx.app.inject({
					method: "GET",
					url: "/sessions",
					headers: { authorization: `Bearer ${access_token}` },
				});
				expect(response.statusCode).toBe(200);
				const body = response.json();
				expect(Array.isArray(body)).toBe(true);
				expect(body).toHaveLength(1);
				expect(body[0]).toHaveProperty("id");
			});
		});
	});

	describe("DELETE /sessions", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "DELETE",
					url: "/sessions",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			it("should delete all sessions for the logged-in user, except the current session that the user is using", async () => {
				await signup(ctx);
				// Simulate two active sessions for the same user (e.g. two devices).
				const currentSession = (await login(ctx)).json();
				await login(ctx);
				expect(ctx.sessions).toHaveLength(2);

				const response = await ctx.app.inject({
					method: "DELETE",
					url: "/sessions",
					headers: { authorization: `Bearer ${currentSession.access_token}` },
				});

				expect(response.statusCode).toBe(200);
				expect(ctx.sessions).toHaveLength(1);
				expect(ctx.sessions[0].access_token).toBe(currentSession.access_token);
			});
		});
	});

	describe("DELETE /sessions/:id", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "DELETE",
					url: "/sessions/1",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is no session found for the session id provided", () => {
			it("should respond with a HTTP status 404 and not found payload", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				const response = await ctx.app.inject({
					method: "DELETE",
					url: "/sessions/999999",
					headers: { authorization: `Bearer ${access_token}` },
				});
				expect(response.statusCode).toBe(404);
				expect(response.json()).toMatchObject({ error: "Session not found" });
			});
		});

		describe("when the found session access is the same as the current session", () => {
			// NOTE: the current implementation returns 409 (not 400) for this
			// conflict, with an { error: "conflict", message } payload.
			it("should respond with a HTTP status 409 and inform the user to use the logout endpoint to end the session", async () => {
				const { access_token } = await signupAndLoginAsApi(ctx);
				const currentSessionId = ctx.sessions[0].id;
				const response = await ctx.app.inject({
					method: "DELETE",
					url: `/sessions/${currentSessionId}`,
					headers: { authorization: `Bearer ${access_token}` },
				});
				expect(response.statusCode).toBe(409);
				expect(response.json()).toMatchObject({
					error: "conflict",
					message: expect.stringMatching(/logout/i),
				});
			});
		});

		describe("when the found session access is different from the current session", () => {
			it("should respond with a HTTP status 200 and delete the session", async () => {
				await signup(ctx);
				const currentSession = (await login(ctx)).json();
				await login(ctx);
				expect(ctx.sessions).toHaveLength(2);
				const otherSession = ctx.sessions.find(
					(s) => s.access_token !== currentSession.access_token,
				);

				const response = await ctx.app.inject({
					method: "DELETE",
					url: `/sessions/${otherSession?.id}`,
					headers: { authorization: `Bearer ${currentSession.access_token}` },
				});

				expect(response.statusCode).toBe(200);
				expect(ctx.sessions).toHaveLength(1);
				expect(ctx.sessions[0].access_token).toBe(currentSession.access_token);
			});
		});
	});
});
