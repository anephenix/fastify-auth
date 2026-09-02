import fs from "node:fs";
import path from "node:path";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authRoutesTemplate } from "../../../src/generators/wizard/authRoutesTemplate.js";
import { db } from "./fakeDb.js";
import User from "./models/User.js";

/*
  Proves the magic-link + TOTP (no password) wizard recipe generates a
  working app - the case unit tests at the template level can't catch:
  whether the MFA gate this feature exists for actually fires when a real
  Fastify instance handles a real /magic-links/verify request.

  There's no /signup or /login route in this recipe (both are owned by the
  password strategy, which isn't selected here), so the test seeds a user
  directly through the fake User model instead of via HTTP. /auth/mfa/setup
  and /auth/mfa/disable are still reachable though - they're part of the
  TOTP block, which is generated whenever mfa is "totp" regardless of
  whether password login was selected.
*/

const routesDir = path.join(import.meta.dirname, "routes");
const routesFile = path.join(routesDir, "auth.ts");

let app: FastifyInstance;

beforeAll(async () => {
	fs.mkdirSync(routesDir, { recursive: true });
	fs.writeFileSync(
		routesFile,
		authRoutesTemplate({
			password: false,
			magicLink: true,
			mfa: "totp",
			forgotPassword: false,
		}),
	);

	const { registerAuthRoutes } = await import("./routes/auth.js");

	app = Fastify();
	await app.register(cookie);
	registerAuthRoutes(app);
	await app.ready();

	await User.query().insert({
		username: "dave",
		email: "dave@example.com",
		password: "hunter22",
	});
});

afterAll(async () => {
	await app.close();
	fs.rmSync(routesDir, { recursive: true, force: true });
});

async function requestMagicLink(email: string) {
	const request = await app.inject({
		method: "POST",
		url: "/magic-links",
		payload: { email },
	});
	expect(request.statusCode).toBe(201);
	return db.magicLinks.at(-1);
}

describe("wizard-generated app (magic-link + TOTP, no password)", () => {
	it("supports magic-link login before MFA is enrolled", async () => {
		const record = await requestMagicLink("dave@example.com");

		const verify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: record?.token, code: "123456" },
		});
		expect(verify.statusCode).toBe(201);
		expect(JSON.parse(verify.body)).toHaveProperty("access_token");
	});

	it("enrolls TOTP MFA, then gates magic-link login instead of bypassing it", async () => {
		const login = await requestMagicLink("dave@example.com");
		const verify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: login?.token, code: "123456" },
		});
		const { access_token } = JSON.parse(verify.body);

		const setup = await app.inject({
			method: "POST",
			url: "/auth/mfa/setup",
			headers: { authorization: `Bearer ${access_token}` },
		});
		expect(setup.statusCode).toBe(200);
		expect(JSON.parse(setup.body)).toHaveProperty("qrCodeImageData");

		const user = db.users.find((u) => u.username === "dave");
		expect(user?.mfa_totp_secret).toBeTruthy();

		// A magic link is only a first factor - it must now be gated the
		// same way password login would be, not mint a session directly.
		// This is the exact gap the wizard's magic-links + MFA combo closes
		// (the built-in magic-links strategy has no such check at all).
		const gatedRequest = await requestMagicLink("dave@example.com");
		const gatedVerify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: gatedRequest?.token, code: "123456" },
		});
		expect(gatedVerify.statusCode).toBe(201);
		const gatedBody = JSON.parse(gatedVerify.body);
		expect(gatedBody).toHaveProperty("token");
		expect(gatedBody).not.toHaveProperty("access_token");
	});

	it("completes login via /login/mfa using a real TOTP code, and mints a session", async () => {
		const { authenticator } = await import("otplib");
		const { totpCrypto } = await import("./lib/auth.js");

		const user = db.users.find((u) => u.username === "dave");
		expect(user?.mfa_totp_secret).toBeTruthy();
		const secret = totpCrypto.decrypt(user?.mfa_totp_secret as string);
		const code = authenticator.generate(secret);

		const record = await requestMagicLink("dave@example.com");
		const verify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: record?.token, code: "123456" },
		});
		const { token } = JSON.parse(verify.body);

		const mfa = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token, code },
		});
		expect(mfa.statusCode).toBe(201);
		expect(JSON.parse(mfa.body)).toHaveProperty("access_token");
	});

	it("does not register password or forgot-password routes", async () => {
		const signup = await app.inject({
			method: "POST",
			url: "/signup",
			payload: {},
		});
		expect(signup.statusCode).toBe(404);

		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: {},
		});
		expect(login.statusCode).toBe(404);

		const forgotPassword = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: {},
		});
		expect(forgotPassword.statusCode).toBe(404);
	});
});
