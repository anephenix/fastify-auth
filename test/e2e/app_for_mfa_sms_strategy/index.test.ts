import { beforeEach, describe, expect, it } from "vitest";
import { type BuiltApp, buildApp } from "./index.js";

// ─── Test helpers ─────────────────────────────────────────────────────────────

const ALICE = {
	username: "alice",
	email: "alice@example.com",
	password: "secret123",
};

function seedAlice(ctx: BuiltApp) {
	return ctx.addUser(ALICE);
}

async function requestSmsLogin(
	ctx: BuiltApp,
	overrides: { identifier?: string; password?: string } = {},
) {
	return ctx.app.inject({
		method: "POST",
		url: "/sessions",
		payload: {
			identifier: overrides.identifier ?? ALICE.username,
			password: overrides.password ?? ALICE.password,
		},
	});
}

async function verifyCode(
	ctx: BuiltApp,
	payload: { token?: string; code?: string },
) {
	return ctx.app.inject({
		method: "POST",
		url: "/sessions/verify-code",
		payload,
	});
}

/** Seeds a user and drives a real first-factor login to get a live token/code pair. */
async function triggerSmsLoginForAlice(ctx: BuiltApp) {
	seedAlice(ctx);
	await requestSmsLogin(ctx);
	const sent = ctx.sentSmsCodes.at(-1);
	if (!sent) {
		throw new Error("Expected onSmsCodeCreated to have run");
	}
	return sent;
}

describe("app_for_mfa_sms_strategy", () => {
	let ctx: BuiltApp;

	beforeEach(async () => {
		ctx = buildApp();
		await ctx.app.ready();
	});

	describe("/POST sessions", () => {
		describe("when a user fails to authenticate", () => {
			describe("because no identifier is provided", () => {
				// NOTE: the current implementation returns 401 (not 400) here,
				// since the missing-identifier check throws into the same catch
				// block that handles invalid credentials.
				it("should return a 401 error", async () => {
					const response = await ctx.app.inject({
						method: "POST",
						url: "/sessions",
						payload: { password: ALICE.password },
					});
					expect(response.statusCode).toBe(401);
					expect(response.json().error).toMatch(/username or email/i);
				});
			});

			describe("because the identifier is invalid", () => {
				it("should return a 401 error", async () => {
					seedAlice(ctx);
					const response = await requestSmsLogin(ctx, {
						identifier: "nobody",
					});
					expect(response.statusCode).toBe(401);
					expect(response.json()).toMatchObject({
						error: "Invalid credentials",
					});
				});
			});

			describe("because no password is provided", () => {
				it("should return a 401 error", async () => {
					const response = await ctx.app.inject({
						method: "POST",
						url: "/sessions",
						payload: { identifier: ALICE.username },
					});
					expect(response.statusCode).toBe(401);
					expect(response.json().error).toMatch(/password/i);
				});
			});

			describe("because the password is incorrect", () => {
				it("should return a 401 error", async () => {
					seedAlice(ctx);
					const response = await requestSmsLogin(ctx, { password: "wrong" });
					expect(response.statusCode).toBe(401);
					expect(response.json()).toMatchObject({
						error: "Invalid credentials",
					});
				});
			});
		});

		describe("when a user authenticates successfully", () => {
			// NOTE: the current implementation returns 201 (not 200) here.
			it("should return a 201 response", async () => {
				seedAlice(ctx);
				const response = await requestSmsLogin(ctx);
				expect(response.statusCode).toBe(201);
				const body = response.json();
				expect(body).toHaveProperty("token");
				expect(body.message).toMatch(/SMS code sent/i);
			});

			it("should generate an sms code record", async () => {
				seedAlice(ctx);
				await requestSmsLogin(ctx);
				expect(ctx.smsCodes).toHaveLength(1);
				expect(ctx.smsCodes[0]).toMatchObject({ user_id: ctx.users[0].id });
			});

			it("should send the sms code to the user via a hook", async () => {
				const user = seedAlice(ctx);
				await requestSmsLogin(ctx);
				expect(ctx.sentSmsCodes).toHaveLength(1);
				expect(ctx.sentSmsCodes[0]).toMatchObject({ userId: user.id });
				expect(ctx.sentSmsCodes[0].token).toBe(ctx.smsCodes[0].token);
			});
		});
	});

	describe("/sessions/verify-code", () => {
		describe("when there is no token", () => {
			it("should return a 400 error", async () => {
				const response = await verifyCode(ctx, { code: "123456" });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Token is required" });
			});
		});

		describe("when there is no code", () => {
			it("should return a 400 error", async () => {
				const response = await verifyCode(ctx, { token: "some-token" });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Code is required" });
			});
		});

		describe("when no sms code is found for the token", () => {
			it("should return a 400 error", async () => {
				const response = await verifyCode(ctx, {
					token: "unknown-token",
					code: "123456",
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Invalid token" });
			});
		});

		describe("when the sms code is found, but has already been used", () => {
			it("should return a 400 error", async () => {
				const { token, code } = await triggerSmsLoginForAlice(ctx);
				await ctx.smsCodes[0]
					.$query()
					.patch({ used_at: new Date().toISOString() });
				const response = await verifyCode(ctx, { token, code });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({
					error: "Code has already been used",
				});
			});
		});

		describe("when the sms code is found but has expired", () => {
			it("should return a 400 error", async () => {
				const { token, code } = await triggerSmsLoginForAlice(ctx);
				ctx.smsCodes[0].expires_at = new Date(Date.now() - 1000).toISOString();
				const response = await verifyCode(ctx, { token, code });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Code has expired" });
			});
		});

		describe("when the sms code is found, but the code is invalid", () => {
			it("should return a 400 error", async () => {
				const { token } = await triggerSmsLoginForAlice(ctx);
				const response = await verifyCode(ctx, { token, code: "000000" });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Invalid code" });
			});
		});

		describe("when the sms code is found and the code is valid", () => {
			it("should update the sms code record with the used_at date field set to the current date and time", async () => {
				const { token, code } = await triggerSmsLoginForAlice(ctx);
				expect(ctx.smsCodes[0].used_at).toBeUndefined();
				await verifyCode(ctx, { token, code });
				expect(ctx.smsCodes[0].used_at).toBeTruthy();
			});

			it("should create a session record for the user from the sms code record, with tokens", async () => {
				const { token, code } = await triggerSmsLoginForAlice(ctx);
				await verifyCode(ctx, { token, code });
				expect(ctx.sessions).toHaveLength(1);
				expect(ctx.sessions[0]).toMatchObject({ user_id: ctx.users[0].id });
				expect(ctx.sessions[0]).toHaveProperty("access_token");
				expect(ctx.sessions[0]).toHaveProperty("refresh_token");
			});

			it("should return a 201 response and return the session tokens", async () => {
				const { token, code } = await triggerSmsLoginForAlice(ctx);
				const response = await verifyCode(ctx, { token, code });
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
