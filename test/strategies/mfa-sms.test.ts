import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import { registerMfaSmsStrategy } from "../../src/strategies/mfa-sms.js";
import type {
	AuthFastifyPluginOptions,
	ISmsCodeModelStatic,
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

const mockSmsCode = {
	id: 1,
	user_id: 1,
	token: "sms_token_abc",
	hashed_code: "hashed_code",
	expires_at: new Date(Date.now() + 600_000).toISOString(),
	used_at: undefined,
	codeHasExpired: vi.fn().mockReturnValue(false),
	verifyCode: vi.fn().mockResolvedValue(true),
	$query: vi.fn().mockReturnValue({
		patch: vi.fn().mockResolvedValue(1),
	}),
};

const mockAuth = {
	generateSmsCode: vi.fn().mockResolvedValue({
		token: "sms_token_abc",
		code: "123456",
		hashedCode: "hashed_code",
		expiresAt: new Date(Date.now() + 600_000),
	}),
};

// ─── App builder ─────────────────────────────────────────────────────────────

function buildApp(opts: {
	userAuthResult?: unknown;
	smsFindResult?: unknown;
	onSmsCodeCreated?: () => Promise<void>;
} = {}) {
	const app = Fastify();

	const User = {
		authenticate: vi.fn().mockResolvedValue(
			opts.userAuthResult !== undefined ? opts.userAuthResult : mockUser,
		),
	} as unknown as IUserModelStatic;

	const SmsCode = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue(mockSmsCode),
			findOne: vi.fn().mockResolvedValue(
				opts.smsFindResult !== undefined ? opts.smsFindResult : mockSmsCode,
			),
		}),
	} as unknown as ISmsCodeModelStatic;

	const Session = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue({ id: 1, ...tokenObj }),
		}),
		generateTokens: vi.fn().mockReturnValue(tokenObj),
	} as unknown as ISessionModelStatic;

	const pluginOpts: AuthFastifyPluginOptions = {
		strategy: "mfa-sms",
		auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
		models: { User, Session, SmsCode },
		hooks: opts.onSmsCodeCreated
			? { onSmsCodeCreated: opts.onSmsCodeCreated }
			: undefined,
	};

	registerMfaSmsStrategy(app, pluginOpts);
	return { app, User, SmsCode, Session };
}

// ─── POST /sessions (first-factor auth) ──────────────────────────────────────

describe("POST /sessions", () => {
	it("returns 401 when identifier is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions",
			payload: { password: "secret" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json().error).toMatch(/username or email/i);
	});

	it("returns 401 when password is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions",
			payload: { identifier: "testuser" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json().error).toMatch(/password/i);
	});

	it("returns 401 when credentials are invalid", async () => {
		const { app } = buildApp({ userAuthResult: null });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions",
			payload: { identifier: "testuser", password: "wrong" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toMatchObject({ error: "Invalid credentials" });
	});

	it("returns 201 with token on successful authentication", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions",
			payload: { identifier: "testuser", password: "secret" },
		});
		expect(response.statusCode).toBe(201);
		const body = response.json();
		expect(body).toHaveProperty("token");
		expect(body.message).toMatch(/SMS code sent/i);
	});

	it("calls onSmsCodeCreated hook when provided", async () => {
		const hook = vi.fn().mockResolvedValue(undefined);
		const { app } = buildApp({ onSmsCodeCreated: hook });
		await app.ready();
		await app.inject({
			method: "POST",
			url: "/sessions",
			payload: { identifier: "testuser", password: "secret" },
		});
		expect(hook).toHaveBeenCalledOnce();
		expect(hook).toHaveBeenCalledWith(
			expect.objectContaining({ user: mockUser, token: "sms_token_abc" }),
		);
	});
});

// ─── POST /sessions/verify-code ───────────────────────────────────────────────

describe("POST /sessions/verify-code", () => {
	it("returns 400 when token is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Token is required" });
	});

	it("returns 400 when code is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { token: "sms_token_abc" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Code is required" });
	});

	it("returns 400 when token is not found", async () => {
		const { app } = buildApp({ smsFindResult: null });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { token: "bad_token", code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Invalid token" });
	});

	it("returns 400 when code has already been used", async () => {
		const usedSmsCode = {
			...mockSmsCode,
			used_at: new Date().toISOString(),
		};
		const { app } = buildApp({ smsFindResult: usedSmsCode });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { token: "sms_token_abc", code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Code has already been used" });
	});

	it("returns 400 when code has expired", async () => {
		const expiredSmsCode = {
			...mockSmsCode,
			codeHasExpired: vi.fn().mockReturnValue(true),
		};
		const { app } = buildApp({ smsFindResult: expiredSmsCode });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { token: "sms_token_abc", code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Code has expired" });
	});

	it("returns 400 when code is invalid", async () => {
		const invalidCodeSmsCode = {
			...mockSmsCode,
			verifyCode: vi.fn().mockResolvedValue(false),
		};
		const { app } = buildApp({ smsFindResult: invalidCodeSmsCode });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { token: "sms_token_abc", code: "999999" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Invalid code" });
	});

	it("returns 201 with session tokens on successful verification", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/sessions/verify-code",
			payload: { token: "sms_token_abc", code: "123456" },
		});
		expect(response.statusCode).toBe(201);
		const body = response.json();
		expect(body).toHaveProperty("access_token");
		expect(body).toHaveProperty("refresh_token");
	});
});

// ─── Strategy registration ────────────────────────────────────────────────────

describe("registerMfaSmsStrategy", () => {
	it("throws when Session model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const SmsCode = {} as unknown as ISmsCodeModelStatic;
		expect(() =>
			registerMfaSmsStrategy(app, {
				strategy: "mfa-sms",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, SmsCode },
			}),
		).toThrow("Session model is required");
	});

	it("throws when SmsCode model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const Session = {} as unknown as ISessionModelStatic;
		expect(() =>
			registerMfaSmsStrategy(app, {
				strategy: "mfa-sms",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, Session },
			}),
		).toThrow("SmsCode model is required");
	});
});
