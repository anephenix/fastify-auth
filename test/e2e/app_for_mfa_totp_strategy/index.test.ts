import { authenticator } from "otplib";
import { beforeEach, describe, expect, it } from "vitest";
import { type BuiltApp, buildApp, encryptTotpSecret } from "./index.js";

// ─── Test helpers ─────────────────────────────────────────────────────────────

const ALICE = {
	username: "alice",
	email: "alice@example.com",
	password: "secret123",
	mobile_number: "+15550001111",
};

// A real otplib secret, shared across tests that need a known, already-
// enrolled TOTP user — generating a fresh one per test would also work, but
// this keeps `currentTotpCode()` trivial.
const RAW_TOTP_SECRET = authenticator.generateSecret();

function currentTotpCode(): string {
	return authenticator.generate(RAW_TOTP_SECRET);
}

function seedPlainUser(ctx: BuiltApp) {
	return ctx.addUser(ALICE);
}

function seedEnrolledUser(ctx: BuiltApp) {
	return ctx.addUser({
		...ALICE,
		mfa_totp_secret: encryptTotpSecret(RAW_TOTP_SECRET),
	});
}

function authHeaders(session: { access_token: string }) {
	return { authorization: `Bearer ${session.access_token}` };
}

describe("app_for_mfa_totp_strategy", () => {
	let ctx: BuiltApp;

	beforeEach(async () => {
		ctx = buildApp();
		await ctx.app.ready();
	});

	describe("POST /signup", () => {
		describe("When a valid user is provided", () => {
			it("should create a user record in the database", async () => {
				await ctx.app.inject({
					method: "POST",
					url: "/signup",
					payload: ALICE,
				});
				expect(ctx.users).toHaveLength(1);
				expect(ctx.users[0]).toMatchObject({
					username: ALICE.username,
					email: ALICE.email,
					mobile_number: ALICE.mobile_number,
				});
			});

			it("should create a session record in the database", async () => {
				await ctx.app.inject({
					method: "POST",
					url: "/signup",
					payload: ALICE,
				});
				expect(ctx.sessions).toHaveLength(1);
				expect(ctx.sessions[0]).toMatchObject({ user_id: ctx.users[0].id });
			});

			it("should return a HTTP status 201 with the access and refresh tokens", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/signup",
					payload: ALICE,
				});
				expect(response.statusCode).toBe(201);
				const body = response.json();
				expect(body).toHaveProperty("access_token");
				expect(body).toHaveProperty("refresh_token");
				expect(body).toHaveProperty("access_token_expires_at");
				expect(body).toHaveProperty("refresh_token_expires_at");
			});
		});

		describe("When mobile_number is not provided", () => {
			it("should still create the user and return a session (mobile_number is optional)", async () => {
				const { mobile_number: _mobile_number, ...aliceWithoutMobileNumber } =
					ALICE;
				const response = await ctx.app.inject({
					method: "POST",
					url: "/signup",
					payload: aliceWithoutMobileNumber,
				});
				expect(response.statusCode).toBe(201);
				expect(ctx.users).toHaveLength(1);
				expect(ctx.users[0].mobile_number).toBeUndefined();
			});
		});

		describe("When a user is invalid", () => {
			// Such as... missing username, missing email, missing password
			it("should a HTTP status 400, and an explanation of the error", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/signup",
					payload: { username: ALICE.username },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toHaveProperty("error");
				expect(ctx.users).toHaveLength(0);
			});
		});
	});

	describe("POST /login", () => {
		describe("when the login details are correct", () => {
			describe("and the user is using MFA", () => {
				it("should create a MFAToken record in the database", async () => {
					const user = seedEnrolledUser(ctx);
					await ctx.app.inject({
						method: "POST",
						url: "/login",
						payload: { identifier: ALICE.username, password: ALICE.password },
					});
					expect(ctx.mfaTokens).toHaveLength(1);
					expect(ctx.mfaTokens[0]).toMatchObject({ user_id: user.id });
				});

				it("should reply with a HTTP Status 201 and the MFA token in the payload", async () => {
					seedEnrolledUser(ctx);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/login",
						payload: { identifier: ALICE.username, password: ALICE.password },
					});
					expect(response.statusCode).toBe(201);
					const body = response.json();
					expect(body).toHaveProperty("token");
					expect(body).not.toHaveProperty("access_token");
				});
			});

			describe("but the user is not using MFA", () => {
				it("should create a session record in the database", async () => {
					seedPlainUser(ctx);
					await ctx.app.inject({
						method: "POST",
						url: "/login",
						payload: { identifier: ALICE.username, password: ALICE.password },
					});
					expect(ctx.sessions).toHaveLength(1);
				});

				it("should return a HTTP status 201 with the access and refresh tokens", async () => {
					seedPlainUser(ctx);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/login",
						payload: { identifier: ALICE.username, password: ALICE.password },
					});
					expect(response.statusCode).toBe(201);
					const body = response.json();
					expect(body).toHaveProperty("access_token");
					expect(body).toHaveProperty("refresh_token");
				});
			});
		});

		describe("when the login details are not correct", () => {
			// NOTE: the current implementation returns 401 (not 400) here, the
			// same pattern as the sessions/mfa-sms strategies' /login route.
			it("should a HTTP status 401, and an explanation of the error", async () => {
				seedPlainUser(ctx);
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login",
					payload: { identifier: ALICE.username, password: "wrong" },
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});
	});

	// The original test outline didn't cover this route, but it's the route
	// that actually completes the MFA login flow, so it's covered here too.
	describe("POST /login/mfa", () => {
		async function requestMfaToken(ctx: BuiltApp) {
			const user = seedEnrolledUser(ctx);
			const loginResponse = await ctx.app.inject({
				method: "POST",
				url: "/login",
				payload: { identifier: ALICE.username, password: ALICE.password },
			});
			return { user, token: loginResponse.json().token as string };
		}

		describe("when the token or code is missing", () => {
			it("should return a 400 error", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token: "some-token" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json().error).toMatch(/required/i);
			});
		});

		describe("when the MFA token is not found", () => {
			it("should return a 400 error", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token: "unknown-token", code: "123456" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "MFA token not found" });
			});
		});

		describe("when too many attempts have been made", () => {
			it("should return a 400 error", async () => {
				const { token } = await requestMfaToken(ctx);
				ctx.mfaTokens[0].number_of_attempts = ctx.auth.maxMfaAttempts;
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token, code: "123456" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Too many attempts" });
			});
		});

		describe("when the MFA token has already been used", () => {
			it("should return a 400 error", async () => {
				const { token } = await requestMfaToken(ctx);
				ctx.mfaTokens[0].used_at = new Date().toISOString();
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token, code: "123456" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({
					error: "MFA token has already been used",
				});
			});
		});

		describe("when the user for the token no longer has MFA enabled", () => {
			it("should return a 400 error", async () => {
				const { user, token } = await requestMfaToken(ctx);
				user.mfa_totp_secret = null;
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token, code: "123456" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({
					error: "User does not have MFA enabled",
				});
			});
		});

		describe("when the TOTP code is invalid", () => {
			it("should return a 400 error and increment the number of attempts", async () => {
				const { token } = await requestMfaToken(ctx);
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token, code: "000000" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "Invalid code" });
				expect(ctx.mfaTokens[0].number_of_attempts).toBe(1);
			});
		});

		describe("when the TOTP code is valid", () => {
			it("should create a session and return a 201 with session tokens", async () => {
				const { token } = await requestMfaToken(ctx);
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token, code: currentTotpCode() },
				});
				expect(response.statusCode).toBe(201);
				const body = response.json();
				expect(body).toHaveProperty("access_token");
				expect(body).toHaveProperty("refresh_token");
				expect(ctx.mfaTokens[0].used_at).toBeTruthy();
			});
		});

		describe("when a valid recovery code is provided instead of a TOTP code", () => {
			it("should create a session and return a 201 with session tokens", async () => {
				const { user, token } = await requestMfaToken(ctx);
				const rawCode = "a1b2c3d4e5";
				ctx.recoveryCodes.push({
					id: 1,
					user_id: user.id,
					hashed_code: await ctx.auth.hashPassword(rawCode),
				});
				const response = await ctx.app.inject({
					method: "POST",
					url: "/login/mfa",
					payload: { token, recovery_code: rawCode },
				});
				expect(response.statusCode).toBe(201);
				expect(response.json()).toHaveProperty("access_token");
			});
		});
	});

	describe("POST /auth/mfa/recovery-codes", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/recovery-codes",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			describe("but the recovery codes have already been generated", () => {
				it("should respond with a HTTP 400 Status and inform that the codes have already been generated", async () => {
					const user = seedPlainUser(ctx);
					const session = ctx.createSession(user.id);
					ctx.recoveryCodes.push({
						id: 1,
						user_id: user.id,
						hashed_code: "already-generated",
					});
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/recovery-codes",
						headers: authHeaders(session),
					});
					expect(response.statusCode).toBe(400);
					expect(response.json().error).toMatch(/already been generated/i);
				});
			});

			describe("and the recovery codes have not yet been generated", () => {
				it("should generate the recovery codes and return them in a HTTP 201 response", async () => {
					const user = seedPlainUser(ctx);
					const session = ctx.createSession(user.id);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/recovery-codes",
						headers: authHeaders(session),
					});
					expect(response.statusCode).toBe(201);
					const body = response.json();
					expect(Array.isArray(body.codes)).toBe(true);
					expect(body.codes).toHaveLength(10);
					expect(
						ctx.recoveryCodes.filter((rc) => rc.user_id === user.id),
					).toHaveLength(10);
				});
			});
		});
	});

	describe("POST /auth/mfa/setup", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/setup",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			it("should update the user record in the database with the mfa_totp_secret", async () => {
				const user = seedPlainUser(ctx);
				const session = ctx.createSession(user.id);
				expect(user.mfa_totp_secret).toBeNull();
				await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/setup",
					headers: authHeaders(session),
				});
				expect(ctx.users[0].mfa_totp_secret).toBeTruthy();
			});

			it("should generate a QR Code image and return that data in the response", async () => {
				const user = seedPlainUser(ctx);
				const session = ctx.createSession(user.id);
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/setup",
					headers: authHeaders(session),
				});
				expect(response.statusCode).toBe(200);
				expect(response.json().qrCodeImageData).toMatch(
					/^data:image\/png;base64,/,
				);
			});
		});

		describe("when there is an error", () => {
			it("should respond with a HTTP status 500 and an error message", async () => {
				const user = seedPlainUser(ctx);
				const session = ctx.createSession(user.id);
				// Simulate a persistence failure while writing the new secret.
				ctx.users[0].$query = () => ({
					patch: async () => {
						throw new Error("Database write failed");
					},
				});
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/setup",
					headers: authHeaders(session),
				});
				expect(response.statusCode).toBe(500);
				expect(response.json()).toHaveProperty("error");
			});
		});
	});

	describe("POST /auth/mfa/verify", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/verify",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			describe("but the token is invalid", () => {
				it("should respond with a HTTP 400 status and the message of Invalid TOTP token", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/verify",
						headers: authHeaders(session),
						payload: { token: "000000" },
					});
					expect(response.statusCode).toBe(400);
					expect(response.json()).toMatchObject({
						error: "Invalid TOTP token",
					});
				});
			});

			describe("and the token is valid", () => {
				// NOTE: the outline text for this case read "...400 status and the
				// message that the token is valid", which looks like a copy/paste
				// slip from the "invalid" case above — the actual success response
				// is a 200 with a "verified successfully" message.
				it("should respond with a HTTP 200 status and a message that the token is valid", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/verify",
						headers: authHeaders(session),
						payload: { token: currentTotpCode() },
					});
					expect(response.statusCode).toBe(200);
					expect(response.json()).toMatchObject({
						message: "TOTP token verified successfully",
					});
				});
			});
		});
	});

	describe("POST /auth/mfa/disable", () => {
		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/disable",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			describe("but the password is invalid", () => {
				it("should respond with a HTTP 400 status and a message that the password is invalid", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable",
						headers: authHeaders(session),
						payload: { password: "wrong-password", code: currentTotpCode() },
					});
					expect(response.statusCode).toBe(400);
					expect(response.json()).toMatchObject({ error: "Invalid password" });
				});
			});

			describe("but the code is invalid", () => {
				it("should respond with a HTTP 400 status and a message that the MFA TOTP code is invalid", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: "000000" },
					});
					expect(response.statusCode).toBe(400);
					expect(response.json()).toMatchObject({
						error: "Invalid MFA TOTP code",
					});
				});
			});

			describe("and the password and code are valid", () => {
				it("should remove the mfa_totp_secret from the user record in the database", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: currentTotpCode() },
					});
					expect(ctx.users[0].mfa_totp_secret).toBeNull();
				});

				it("should delete from the database all of the recovery codes that are linked to the user", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					ctx.recoveryCodes.push(
						{ id: 1, user_id: user.id, hashed_code: "a" },
						{ id: 2, user_id: user.id, hashed_code: "b" },
					);
					await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: currentTotpCode() },
					});
					expect(
						ctx.recoveryCodes.filter((rc) => rc.user_id === user.id),
					).toHaveLength(0);
				});

				it("should respond with a HTTP 200 status and a message that the MFA TOTP has been disabled", async () => {
					const user = seedEnrolledUser(ctx);
					const session = ctx.createSession(user.id);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: currentTotpCode() },
					});
					expect(response.statusCode).toBe(200);
					expect(response.json()).toMatchObject({
						message: "MFA TOTP disabled successfully",
					});
				});
			});
		});
	});

	describe("POST /auth/mfa/disable-with-recovery-code", () => {
		async function seedEnrolledUserWithRecoveryCode(ctx: BuiltApp) {
			const user = seedEnrolledUser(ctx);
			const rawCode = "f6e5d4c3b2";
			ctx.recoveryCodes.push({
				id: 1,
				user_id: user.id,
				hashed_code: await ctx.auth.hashPassword(rawCode),
			});
			const session = ctx.createSession(user.id);
			return { user, rawCode, session };
		}

		describe("when there is no logged-in user", () => {
			it("should respond with a HTTP status 401 and unauthorized payload", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/auth/mfa/disable-with-recovery-code",
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is a logged-in user", () => {
			describe("but the password is invalid", () => {
				it("should return a 400 response indicating that the password is invalid", async () => {
					const { rawCode, session } =
						await seedEnrolledUserWithRecoveryCode(ctx);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable-with-recovery-code",
						headers: authHeaders(session),
						payload: { password: "wrong-password", code: rawCode },
					});
					expect(response.statusCode).toBe(400);
					expect(response.json()).toMatchObject({ error: "Invalid password" });
				});
			});

			describe("but the recovery code is invalid", () => {
				it("should return a 400 response indicating that the recovery code is invalid", async () => {
					const { session } = await seedEnrolledUserWithRecoveryCode(ctx);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable-with-recovery-code",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: "not-the-right-code" },
					});
					expect(response.statusCode).toBe(400);
					expect(response.json()).toMatchObject({
						error: "Invalid Recovery code",
					});
				});
			});

			describe("and the password and recovery code are valid", () => {
				it("should remove the mfa_totp_secret from the user record in the database", async () => {
					const { user, rawCode, session } =
						await seedEnrolledUserWithRecoveryCode(ctx);
					await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable-with-recovery-code",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: rawCode },
					});
					expect(ctx.users[0].mfa_totp_secret).toBeNull();
					expect(user.id).toBe(ctx.users[0].id);
				});

				it("should delete from the database all of the recovery codes that are linked to the user", async () => {
					const { user, rawCode, session } =
						await seedEnrolledUserWithRecoveryCode(ctx);
					await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable-with-recovery-code",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: rawCode },
					});
					expect(
						ctx.recoveryCodes.filter((rc) => rc.user_id === user.id),
					).toHaveLength(0);
				});

				it("should respond with a HTTP 200 status and a message that the MFA TOTP has been disabled", async () => {
					const { rawCode, session } =
						await seedEnrolledUserWithRecoveryCode(ctx);
					const response = await ctx.app.inject({
						method: "POST",
						url: "/auth/mfa/disable-with-recovery-code",
						headers: authHeaders(session),
						payload: { password: ALICE.password, code: rawCode },
					});
					expect(response.statusCode).toBe(200);
					expect(response.json()).toMatchObject({
						message: "MFA TOTP disabled successfully",
					});
				});
			});
		});
	});
});
