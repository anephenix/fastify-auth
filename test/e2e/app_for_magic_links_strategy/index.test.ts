import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { registerMagicLinksStrategy } from "../../../src/strategies/magic-links.js";
import type {
	AuthFastifyPluginOptions,
	IMagicLinkModelStatic,
	ISessionModelStatic,
	IUserModelStatic,
} from "../../../src/types.js";

// Shared fixtures
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

function buildApp(
	opts: {
		userFindResult?: unknown;
		magicLinkInsertResult?: unknown;
		magicLinkVerifyResult?: unknown;
		onMagicLinkCreated?: (...args: unknown[]) => Promise<void>;
	} = {},
) {
	const app = Fastify();
	const User = {
		query: vi.fn().mockReturnValue({
			where: vi.fn().mockReturnValue({
				first: vi
					.fn()
					.mockResolvedValue(
						opts.userFindResult !== undefined ? opts.userFindResult : mockUser,
					),
			}),
		}),
	} as unknown as IUserModelStatic;
	const MagicLink = {
		generateTokens: vi.fn().mockResolvedValue(mockMagicLinkTokens),
		query: vi.fn().mockReturnValue({
			insert: vi
				.fn()
				.mockResolvedValue(
					opts.magicLinkInsertResult !== undefined
						? opts.magicLinkInsertResult
						: {},
				),
		}),
		verifyTokenAndCode: vi.fn().mockImplementation((token, code) => {
			if (opts.magicLinkVerifyResult !== undefined) {
				if (opts.magicLinkVerifyResult instanceof Error) {
					return Promise.reject(opts.magicLinkVerifyResult);
				}
				return Promise.resolve(opts.magicLinkVerifyResult);
			}
			if (
				token === mockMagicLinkTokens.token &&
				code === mockMagicLinkTokens.code
			) {
				return Promise.resolve({ userId: mockUser.id });
			}
			return Promise.reject(new Error("Invalid or expired token"));
		}),
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

describe("app_for_magic_links_strategy", () => {
	describe("POST /magic-links", () => {
		it("should return a 400 error explaining that an email address is required", async () => {
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

		it("should return a 400 error explaining that the email address is invalid", async () => {
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

		it("should return a 201 response", async () => {
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

		it("should trigger the onMagicLinkCreated hook with the user, token, code, and tokenExpiresAt", async () => {
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
					tokenExpiresAt: mockMagicLinkTokens.tokenExpiresAt,
				}),
			);
		});
	});

	describe("POST /magic-links/verify", () => {
		it("should return a 400 error explaining that a token and code are required", async () => {
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

		it("should return a 400 error explaining that the token or code is invalid", async () => {
			const { app, MagicLink } = buildApp();
			(
				MagicLink.verifyTokenAndCode as ReturnType<typeof vi.fn>
			).mockRejectedValue(new Error("Invalid or expired token"));
			await app.ready();
			const response = await app.inject({
				method: "POST",
				url: "/magic-links/verify",
				payload: { token: "bad_token", code: "000000" },
			});
			expect(response.statusCode).toBe(400);
			expect(response.json().error).toMatch(/invalid or expired/i);
		});

		it("should return a 201 response", async () => {
			const { app } = buildApp();
			await app.ready();
			const response = await app.inject({
				method: "POST",
				url: "/magic-links/verify",
				payload: {
					token: mockMagicLinkTokens.token,
					code: mockMagicLinkTokens.code,
				},
			});
			expect(response.statusCode).toBe(201);
		});

		it("should create a Session record for the user", async () => {
			const { app, Session } = buildApp();
			await app.ready();
			await app.inject({
				method: "POST",
				url: "/magic-links/verify",
				payload: {
					token: mockMagicLinkTokens.token,
					code: mockMagicLinkTokens.code,
				},
			});
			expect(Session.query().insert).toHaveBeenCalledWith(
				expect.objectContaining({ user_id: mockUser.id }),
			);
		});

		it("should return the access_token, refresh_token, and token expiry timestamps in the response", async () => {
			const { app } = buildApp();
			await app.ready();
			const response = await app.inject({
				method: "POST",
				url: "/magic-links/verify",
				payload: {
					token: mockMagicLinkTokens.token,
					code: mockMagicLinkTokens.code,
				},
			});
			const body = response.json();
			expect(body).toHaveProperty("access_token");
			expect(body).toHaveProperty("refresh_token");
			expect(body).toHaveProperty("access_token_expires_at");
			expect(body).toHaveProperty("refresh_token_expires_at");
		});
	});
});
