import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import { registerMagicLinksStrategy } from "../../src/strategies/magic-links.js";
import type {
	AuthFastifyPluginOptions,
	IMagicLinkModelStatic,
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

const mockMagicLinkTokens = {
	token: "magic_token_abc",
	tokenExpiresAt: new Date(Date.now() + 3_600_000),
	code: "123456",
	hashedCode: "hashed_123456",
};

// ─── App builder ─────────────────────────────────────────────────────────────

function buildApp(opts: {
	userFindResult?: unknown;
	magicLinkInsertResult?: unknown;
	magicLinkVerifyResult?: unknown;
	onMagicLinkCreated?: () => Promise<void>;
} = {}) {
	const app = Fastify();

	const User = {
		query: vi.fn().mockReturnValue({
			where: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(
					opts.userFindResult !== undefined ? opts.userFindResult : mockUser,
				),
			}),
		}),
	} as unknown as IUserModelStatic;

	const MagicLink = {
		generateTokens: vi.fn().mockResolvedValue(mockMagicLinkTokens),
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue(
				opts.magicLinkInsertResult !== undefined ? opts.magicLinkInsertResult : {},
			),
		}),
		verifyTokenAndCode: vi.fn().mockResolvedValue(
			opts.magicLinkVerifyResult !== undefined
				? opts.magicLinkVerifyResult
				: { userId: 1 },
		),
	} as unknown as IMagicLinkModelStatic;

	const Session = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue({ id: 1, ...tokenObj }),
		}),
		generateTokens: vi.fn().mockReturnValue(tokenObj),
	} as unknown as ISessionModelStatic;

	const pluginOpts: AuthFastifyPluginOptions = {
		strategy: "magic-links",
		auth: {} as AuthFastifyPluginOptions["auth"],
		models: { User, Session, MagicLink },
		hooks: opts.onMagicLinkCreated
			? { onMagicLinkCreated: opts.onMagicLinkCreated }
			: undefined,
	};

	registerMagicLinksStrategy(app, pluginOpts);
	return { app, User, MagicLink, Session };
}

// ─── POST /magic-links ────────────────────────────────────────────────────────

describe("POST /magic-links", () => {
	it("returns 400 when email is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: {},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/email/i);
	});

	it("returns 400 for an invalid email address", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "not-an-email" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/invalid email/i);
	});

	it("returns 400 when no user is found for the email", async () => {
		const { app } = buildApp({ userFindResult: null });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "unknown@example.com" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/user not found/i);
	});

	it("returns 201 and creates a magic link on success", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "test@example.com" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.json()).toMatchObject({ message: "Magic link created" });
	});

	it("calls onMagicLinkCreated hook when provided", async () => {
		const hook = vi.fn().mockResolvedValue(undefined);
		const { app } = buildApp({ onMagicLinkCreated: hook });
		await app.ready();
		await app.inject({
			method: "POST",
			url: "/magic-links",
			payload: { email: "test@example.com" },
		});
		expect(hook).toHaveBeenCalledOnce();
		expect(hook).toHaveBeenCalledWith(
			expect.objectContaining({
				user: mockUser,
				token: mockMagicLinkTokens.token,
				code: mockMagicLinkTokens.code,
			}),
		);
	});
});

// ─── POST /magic-links/verify ─────────────────────────────────────────────────

describe("POST /magic-links/verify", () => {
	it("returns 400 when token or code is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: "abc" }, // missing code
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/required/i);
	});

	it("returns 400 when verification fails", async () => {
		const { app, MagicLink } = buildApp();
		(MagicLink.verifyTokenAndCode as ReturnType<typeof vi.fn>).mockRejectedValue(
			new Error("Invalid or expired token"),
		);
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: "bad_token", code: "000000" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/invalid or expired/i);
	});

	it("returns 201 with session tokens on successful verification", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/magic-links/verify",
			payload: { token: "magic_token_abc", code: "123456" },
		});
		expect(response.statusCode).toBe(201);
		const body = response.json();
		expect(body).toHaveProperty("access_token");
		expect(body).toHaveProperty("refresh_token");
	});
});

// ─── Strategy registration ────────────────────────────────────────────────────

describe("registerMagicLinksStrategy", () => {
	it("throws when Session model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const MagicLink = {} as unknown as IMagicLinkModelStatic;
		expect(() =>
			registerMagicLinksStrategy(app, {
				strategy: "magic-links",
				auth: {} as AuthFastifyPluginOptions["auth"],
				models: { User, MagicLink },
			}),
		).toThrow("Session model is required");
	});

	it("throws when MagicLink model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const Session = {} as unknown as ISessionModelStatic;
		expect(() =>
			registerMagicLinksStrategy(app, {
				strategy: "magic-links",
				auth: {} as AuthFastifyPluginOptions["auth"],
				models: { User, Session },
			}),
		).toThrow("MagicLink model is required");
	});
});
