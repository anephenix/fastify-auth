import fs from "node:fs";
import path from "node:path";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authRoutesTemplate } from "../../../src/generators/wizard/authRoutesTemplate.js";

/*
  Proves the simplest wizard recipe (password login only, no magic-link/
  TOTP/forgotten-password) generates a minimal, working app - and that the
  routes for features that weren't selected genuinely aren't registered.
*/

const routesDir = path.join(import.meta.dirname, "routes");
const routesFile = path.join(routesDir, "auth.ts");

let app: FastifyInstance;

beforeAll(async () => {
	fs.mkdirSync(routesDir, { recursive: true });
	fs.writeFileSync(
		routesFile,
		authRoutesTemplate({
			password: true,
			magicLink: false,
			totp: false,
			forgotPassword: false,
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

describe("wizard-generated app (password login only)", () => {
	it("supports signup, login and full session management", async () => {
		const signup = await app.inject({
			method: "POST",
			url: "/signup",
			payload: {
				username: "bob",
				email: "bob@example.com",
				password: "hunter22",
			},
		});
		expect(signup.statusCode).toBe(201);

		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "bob", password: "hunter22" },
		});
		expect(login.statusCode).toBe(201);
		const { access_token, refresh_token } = JSON.parse(login.body);
		// no MFA selected, so /login always returns a full session
		expect(access_token).toBeTruthy();

		const profile = await app.inject({
			method: "GET",
			url: "/profile",
			headers: { authorization: `Bearer ${access_token}` },
		});
		expect(profile.statusCode).toBe(200);
		expect(JSON.parse(profile.body).email).toBe("bob@example.com");

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

	it("rejects invalid credentials", async () => {
		const login = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "bob", password: "wrong-password" },
		});
		expect(login.statusCode).toBe(401);
	});

	it("does not register magic-link, TOTP, or forgot-password routes", async () => {
		const magicLink = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "bob@example.com" },
		});
		expect(magicLink.statusCode).toBe(404);

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
