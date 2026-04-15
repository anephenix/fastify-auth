import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import { registerForgottenPasswordStrategy } from "../../src/strategies/forgotten-password.js";
import type {
	AuthFastifyPluginOptions,
	IForgotPasswordModelStatic,
	IUserModelStatic,
} from "../../src/types.js";

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const mockUser = {
	id: 1,
	username: "testuser",
	email: "test@example.com",
	updatePassword: vi.fn().mockResolvedValue(undefined),
};

const mockForgotPasswordRecord = {
	id: 1,
	user_id: 1,
	selector: "test_selector",
	token_hash: "hashed_token",
	expires_at: new Date(Date.now() + 3_600_000), // not expired
	used_at: null as Date | null,
	markAsUsed: vi.fn().mockResolvedValue(undefined),
};

const mockAuth = {
	normalize: vi.fn().mockImplementation((s: string) => s.toLowerCase()),
	validatePassword: vi.fn().mockReturnValue(true),
	verifyPassword: vi.fn().mockResolvedValue(true),
};

// ─── App builder ─────────────────────────────────────────────────────────────

function buildApp(opts: {
	forgotPasswordRecord?: unknown;
	userResult?: unknown;
	onForgotPasswordRequested?: () => Promise<void>;
} = {}) {
	const app = Fastify();

	const User = {
		query: vi.fn().mockReturnValue({
			findById: vi.fn().mockResolvedValue(
				opts.userResult !== undefined ? opts.userResult : mockUser,
			),
		}),
	} as unknown as IUserModelStatic;

	const ForgotPassword = {
		query: vi.fn().mockReturnValue({
			where: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(
					opts.forgotPasswordRecord !== undefined
						? opts.forgotPasswordRecord
						: mockForgotPasswordRecord,
				),
			}),
		}),
	} as unknown as IForgotPasswordModelStatic;

	const pluginOpts: AuthFastifyPluginOptions = {
		strategy: "forgotten-password",
		auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
		models: { User, ForgotPassword },
		hooks: opts.onForgotPasswordRequested
			? { onForgotPasswordRequested: opts.onForgotPasswordRequested }
			: undefined,
	};

	registerForgottenPasswordStrategy(app, pluginOpts);
	return { app, User, ForgotPassword };
}

// ─── POST /forgot-password ────────────────────────────────────────────────────

describe("POST /forgot-password", () => {
	it("returns 400 when identifier is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: {},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Invalid identifier" });
	});

	it("returns 400 when identifier contains invalid characters", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: { identifier: "bad identifier with spaces!" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Invalid identifier" });
	});

	it("returns a neutral message for a valid email identifier", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: { identifier: "test@example.com" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json().message).toMatch(/password reset instructions/i);
	});

	it("returns a neutral message for a valid username identifier", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: { identifier: "testuser" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json().message).toMatch(/password reset instructions/i);
	});

	it("calls onForgotPasswordRequested hook with correct params for email", async () => {
		const hook = vi.fn().mockResolvedValue(undefined);
		const { app } = buildApp({ onForgotPasswordRequested: hook });
		await app.ready();
		await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: { identifier: "test@example.com" },
		});
		expect(hook).toHaveBeenCalledOnce();
		expect(hook).toHaveBeenCalledWith(
			expect.objectContaining({ isEmail: true }),
		);
	});

	it("calls onForgotPasswordRequested hook with isEmail: false for username", async () => {
		const hook = vi.fn().mockResolvedValue(undefined);
		const { app } = buildApp({ onForgotPasswordRequested: hook });
		await app.ready();
		await app.inject({
			method: "POST",
			url: "/forgot-password",
			payload: { identifier: "testuser" },
		});
		expect(hook).toHaveBeenCalledWith(
			expect.objectContaining({ isEmail: false }),
		);
	});
});

// ─── GET /reset-password/:selector ───────────────────────────────────────────

describe("GET /reset-password/:selector", () => {
	it("returns 400 when token query param is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/reset-password/test_selector",
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/invalid/i);
	});

	it("returns 400 when selector is not found", async () => {
		const { app } = buildApp({ forgotPasswordRecord: null });
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/reset-password/bad_selector?token=some_token",
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/invalid/i);
	});

	it("returns 400 when the reset token has expired", async () => {
		const expired = {
			...mockForgotPasswordRecord,
			expires_at: new Date(Date.now() - 1000),
		};
		const { app } = buildApp({ forgotPasswordRecord: expired });
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/reset-password/test_selector?token=some_token",
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/expired/i);
	});

	it("returns 400 when the token has already been used", async () => {
		const used = {
			...mockForgotPasswordRecord,
			used_at: new Date(),
		};
		const { app } = buildApp({ forgotPasswordRecord: used });
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/reset-password/test_selector?token=some_token",
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/already been used/i);
	});

	it("returns 400 when the token does not match the hash", async () => {
		const { app } = buildApp();
		mockAuth.verifyPassword.mockResolvedValueOnce(false);
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/reset-password/test_selector?token=wrong_token",
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/invalid/i);
	});

	it("returns 200 when the token is valid", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "GET",
			url: "/reset-password/test_selector?token=valid_token",
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toMatchObject({ message: "Password reset token is valid" });
	});
});

// ─── POST /reset-password ─────────────────────────────────────────────────────

describe("POST /reset-password", () => {
	it("returns 400 when password is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password_confirmation: "NewPass123!",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/required/i);
	});

	it("returns 400 when passwords do not match", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password: "NewPass123!",
				password_confirmation: "DifferentPass!",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/do not match/i);
	});

	it("returns 400 when password fails validation rules", async () => {
		mockAuth.validatePassword.mockReturnValueOnce(false);
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password: "weak",
				password_confirmation: "weak",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/validation/i);
	});

	it("returns 400 when the selector is not found", async () => {
		const { app } = buildApp({ forgotPasswordRecord: null });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "bad_selector",
				token: "valid_token",
				password: "NewPass123!",
				password_confirmation: "NewPass123!",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/invalid/i);
	});

	it("returns 400 when the reset token has expired", async () => {
		const expired = {
			...mockForgotPasswordRecord,
			expires_at: new Date(Date.now() - 1000),
		};
		const { app } = buildApp({ forgotPasswordRecord: expired });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password: "NewPass123!",
				password_confirmation: "NewPass123!",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/expired/i);
	});

	it("returns 400 when the token has already been used", async () => {
		const used = {
			...mockForgotPasswordRecord,
			used_at: new Date(),
		};
		const { app } = buildApp({ forgotPasswordRecord: used });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password: "NewPass123!",
				password_confirmation: "NewPass123!",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/already been used/i);
	});

	it("returns 400 when the user is not found", async () => {
		const { app } = buildApp({ userResult: null });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password: "NewPass123!",
				password_confirmation: "NewPass123!",
			},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/user not found/i);
	});

	it("resets the password and returns 200 on success", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/reset-password",
			payload: {
				selector: "test_selector",
				token: "valid_token",
				password: "NewPass123!",
				password_confirmation: "NewPass123!",
			},
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toMatchObject({ message: "Password reset successfully" });
	});
});

// ─── Strategy registration ────────────────────────────────────────────────────

describe("registerForgottenPasswordStrategy", () => {
	it("throws when ForgotPassword model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		expect(() =>
			registerForgottenPasswordStrategy(app, {
				strategy: "forgotten-password",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User },
			}),
		).toThrow("ForgotPassword model is required");
	});
});
