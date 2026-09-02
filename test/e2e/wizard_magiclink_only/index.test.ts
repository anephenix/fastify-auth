import fs from "node:fs";
import path from "node:path";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authRoutesTemplate } from "../../../src/generators/wizard/authRoutesTemplate.js";
import { db } from "./fakeDb.js";
import User from "./models/User.js";

/*
  Proves the magic-link-only wizard recipe (no password login, no MFA, no
  forgotten-password) generates a minimal, working app - and that the
  routes for features that weren't selected genuinely aren't registered.

  There's no /signup route in this recipe (that's owned by the password
  strategy, which isn't selected here), so the test seeds a user directly
  through the fake User model instead of via HTTP - matching how a real
  app without password login would create accounts (e.g. an admin import,
  or a separate custom signup route).
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
			mfa: "none",
			forgotPassword: false,
		}),
	);

	const { registerAuthRoutes } = await import("./routes/auth.js");

	app = Fastify();
	await app.register(cookie);
	registerAuthRoutes(app);
	await app.ready();

	await User.query().insert({
		username: "carol",
		email: "carol@example.com",
		password: "hunter22",
	});
});

afterAll(async () => {
	await app.close();
	fs.rmSync(routesDir, { recursive: true, force: true });
});

describe("wizard-generated app (magic-link login only)", () => {
	it("supports magic-link login and full session management", async () => {
		const request = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "carol@example.com" },
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
		const { access_token, refresh_token } = JSON.parse(verify.body);
		expect(access_token).toBeTruthy();

		const profile = await app.inject({
			method: "GET",
			url: "/profile",
			headers: { authorization: `Bearer ${access_token}` },
		});
		expect(profile.statusCode).toBe(200);
		expect(JSON.parse(profile.body).email).toBe("carol@example.com");

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

	it("rejects an unknown email and a reused/invalid code", async () => {
		const unknownEmail = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "nobody@example.com" },
		});
		expect(unknownEmail.statusCode).toBe(400);

		const invalidVerify = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: "not-a-real-token", code: "123456" },
		});
		expect(invalidVerify.statusCode).toBe(400);
	});

	it("does not register password, TOTP, or forgot-password routes", async () => {
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

		const loginMfa = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: {},
		});
		expect(loginMfa.statusCode).toBe(404);

		const forgotPassword = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: {},
		});
		expect(forgotPassword.statusCode).toBe(404);
	});
});
