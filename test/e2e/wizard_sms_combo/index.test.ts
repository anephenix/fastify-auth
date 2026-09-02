import fs from "node:fs";
import path from "node:path";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { authRoutesTemplate } from "../../../src/generators/wizard/authRoutesTemplate.js";
import { db } from "./fakeDb.js";

/*
  Proves the wizard's generated code actually runs, for the full combo with
  mfa: "sms" (password + magic-link + SMS MFA + forgotten-password) - not
  just that the template strings look right. routes/auth.ts is written
  fresh from the real authRoutesTemplate() output before each run
  (gitignored, never committed); models/*.ts and lib/auth.ts are
  hand-written fakes/real Auth instance committed alongside this test.

  Mirrors wizard_full_combo's TOTP proof: a user with SMS MFA enrolled
  gets MFA-gated on BOTH password login AND magic-link login - the
  built-in mfa-sms strategy has no per-user opt-in, and the built-in
  magic-links strategy has no MFA check at all, so this combination isn't
  achievable with any single built-in strategy.
*/

const routesDir = path.join(import.meta.dirname, "routes");
const routesFile = path.join(routesDir, "auth.ts");

let app: FastifyInstance;

function captureSmsCode(logSpy: ReturnType<typeof vi.spyOn>): string {
	const logMessage = logSpy.mock.calls
		.map((args) => args.join(" "))
		.find((msg) => msg.includes("SMS MFA code for"));
	const code = logMessage?.match(/: ([0-9a-f]+)$/i)?.[1];
	expect(code).toBeTruthy();
	return code as string;
}

beforeAll(async () => {
	fs.mkdirSync(routesDir, { recursive: true });
	fs.writeFileSync(
		routesFile,
		authRoutesTemplate({
			password: true,
			magicLink: true,
			mfa: "sms",
			forgotPassword: true,
		}),
	);

	const { registerAuthRoutes } = await import("./routes/auth.js");

	app = Fastify();
	await app.register(cookie);
	registerAuthRoutes(app);
	await app.ready();
});

afterAll(async () => {
	await app.close();
	fs.rmSync(routesDir, { recursive: true, force: true });
});

describe("wizard-generated app (password + magic-link + SMS MFA + forgotten-password)", () => {
	it("supports signup and password login (no MFA yet)", async () => {
		const signup = await app.inject({
			method: "POST",
			url: "/signup",
			payload: {
				username: "alice",
				email: "alice@example.com",
				password: "hunter22",
			},
		});
		expect(signup.statusCode).toBe(201);

		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "hunter22" },
		});
		expect(login.statusCode).toBe(201);
		expect(JSON.parse(login.body)).toHaveProperty("access_token");
	});

	it("supports magic-link login for the same user (no MFA yet)", async () => {
		const request = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "alice@example.com" },
		});
		expect(request.statusCode).toBe(201);

		const record = db.magicLinks.at(-1);
		expect(record).toBeDefined();

		const verify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: record?.token, code: "123456" },
		});
		expect(verify.statusCode).toBe(201);
		expect(JSON.parse(verify.body)).toHaveProperty("access_token");
	});

	it("enrolls the user in SMS MFA, then gates BOTH password and magic-link login", async () => {
		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "hunter22" },
		});
		const { access_token } = JSON.parse(login.body);

		const setup = await app.inject({
			method: "POST",
			url: "/auth/mfa/sms/setup",
			headers: { authorization: `Bearer ${access_token}` },
			payload: { mobile_number: "+15551234567" },
		});
		expect(setup.statusCode).toBe(200);

		const user = db.users.find((u) => u.username === "alice");
		expect(user?.sms_mfa_enabled).toBe(true);
		expect(user?.mobile_number).toBe("+15551234567");

		// The user now has sms_mfa_enabled - password login must be gated.
		const gatedPasswordLogin = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "hunter22" },
		});
		expect(gatedPasswordLogin.statusCode).toBe(201);
		const passwordLoginBody = JSON.parse(gatedPasswordLogin.body);
		expect(passwordLoginBody).toHaveProperty("token");
		expect(passwordLoginBody).not.toHaveProperty("access_token");

		// And magic-link login must ALSO be gated - the same fix TOTP mode
		// gets, extended to SMS.
		const magicLinkReq = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "alice@example.com" },
		});
		const record = db.magicLinks.at(-1);
		const gatedMagicLinkVerify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: record?.token, code: "123456" },
		});
		expect(magicLinkReq.statusCode).toBe(201);
		expect(gatedMagicLinkVerify.statusCode).toBe(201);
		const magicLinkVerifyBody = JSON.parse(gatedMagicLinkVerify.body);
		expect(magicLinkVerifyBody).toHaveProperty("token");
		expect(magicLinkVerifyBody).not.toHaveProperty("access_token");
	});

	it("completes login via /login/mfa using the SMS code, and mints a session", async () => {
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "hunter22" },
		});
		const { token } = JSON.parse(login.body);
		const code = captureSmsCode(logSpy);
		logSpy.mockRestore();

		const mfa = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token, code },
		});
		expect(mfa.statusCode).toBe(201);
		expect(JSON.parse(mfa.body)).toHaveProperty("access_token");

		// The code is single-use - replaying it must fail.
		const replay = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token, code },
		});
		expect(replay.statusCode).toBe(400);
	});

	it("supports forgotten-password: reset flows through to a fresh (still MFA-gated) login", async () => {
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

		const forgot = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: { identifier: "alice@example.com" },
		});
		expect(forgot.statusCode).toBe(200);

		const record = db.forgotPasswords.at(-1);
		expect(record).toBeDefined();

		const logMessage = logSpy.mock.calls
			.map((args) => args.join(" "))
			.find((msg) => msg.includes("Password reset link"));
		logSpy.mockRestore();
		const resetToken = logMessage?.match(/token=([a-f0-9]+)/)?.[1];
		expect(resetToken).toBeTruthy();

		const reset = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: record?.selector,
				token: resetToken,
				password: "newpassword123",
				password_confirmation: "newpassword123",
			},
		});
		expect(reset.statusCode).toBe(200);

		// The user still has SMS MFA enabled from an earlier test, so logging
		// in with the NEW password should return an mfa token, not a session.
		const loginWithNewPassword = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "newpassword123" },
		});
		expect(loginWithNewPassword.statusCode).toBe(201);
		expect(JSON.parse(loginWithNewPassword.body)).toHaveProperty("token");
	});

	it("allows the user to disable SMS MFA, after which login is no longer gated", async () => {
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "newpassword123" },
		});
		const { token } = JSON.parse(login.body);
		const code = captureSmsCode(logSpy);
		logSpy.mockRestore();

		const mfa = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token, code },
		});
		const { access_token } = JSON.parse(mfa.body);

		const disable = await app.inject({
			method: "POST",
			url: "/auth/mfa/sms/disable",
			headers: { authorization: `Bearer ${access_token}` },
			payload: { password: "newpassword123" },
		});
		expect(disable.statusCode).toBe(200);

		const login2 = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "newpassword123" },
		});
		expect(login2.statusCode).toBe(201);
		expect(JSON.parse(login2.body)).toHaveProperty("access_token");
	});

	it("supports full session management: profile, list, refresh, logout", async () => {
		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "alice", password: "newpassword123" },
		});
		const { access_token, refresh_token } = JSON.parse(login.body);

		const profile = await app.inject({
			method: "GET",
			url: "/profile",
			headers: { authorization: `Bearer ${access_token}` },
		});
		expect(profile.statusCode).toBe(200);
		expect(JSON.parse(profile.body).email).toBe("alice@example.com");

		const sessions = await app.inject({
			method: "GET",
			url: "/sessions",
			headers: { authorization: `Bearer ${access_token}` },
		});
		expect(sessions.statusCode).toBe(200);
		expect(Array.isArray(JSON.parse(sessions.body))).toBe(true);

		const refresh = await app.inject({
			method: "POST",
			url: "/auth/refresh",
			payload: { refresh_token },
		});
		expect(refresh.statusCode).toBe(201);
		const { access_token: refreshedAccessToken } = JSON.parse(refresh.body);

		const logout = await app.inject({
			method: "POST",
			url: "/logout",
			headers: { authorization: `Bearer ${refreshedAccessToken}` },
		});
		expect(logout.statusCode).toBe(200);
	});
});
