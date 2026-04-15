import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import { registerMfaTotpStrategy } from "../../src/strategies/mfa-totp.js";
import type {
	AuthFastifyPluginOptions,
	IMfaTokenModelStatic,
	IRecoveryCodeModelStatic,
	ISessionModelStatic,
	IUserModelStatic,
} from "../../src/types.js";

// ─── Mocks ────────────────────────────────────────────────────────────────────

vi.mock("otplib", () => ({
	authenticator: {
		generateSecret: vi.fn().mockReturnValue("TESTSECRETKEY"),
		keyuri: vi.fn().mockReturnValue("otpauth://totp/test"),
		check: vi.fn().mockReturnValue(true),
	},
}));

vi.mock("qrcode", () => ({
	default: {
		toDataURL: vi.fn().mockResolvedValue("data:image/png;base64,test"),
	},
}));

// ─── Shared fixtures ──────────────────────────────────────────────────────────

// A valid 64-character hex key for AES-256-GCM encryption
const TEST_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const mockUser = {
	id: 1,
	username: "testuser",
	email: "test@example.com",
	mfa_totp_secret: null as string | null,
	isUsingMFA: false,
	$query: vi.fn().mockReturnValue({
		patch: vi.fn().mockResolvedValue(1),
	}),
	$relatedQuery: vi.fn().mockReturnValue({
		where: vi.fn().mockReturnValue({
			delete: vi.fn().mockResolvedValue(1),
		}),
		delete: vi.fn().mockResolvedValue(1),
	}),
};

const tokenObj = {
	access_token: "test_access_token",
	access_token_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
	refresh_token: "test_refresh_token",
	refresh_token_expires_at: new Date(Date.now() + 86_400_000).toISOString(),
};

const mockMfaToken = {
	id: 1,
	user_id: 1,
	token: "mfa_token_abc",
	expires_at: new Date(Date.now() + 600_000).toISOString(),
	used_at: undefined as string | undefined,
	number_of_attempts: 0,
	$query: vi.fn().mockReturnValue({
		patch: vi.fn().mockResolvedValue(1),
		increment: vi.fn().mockResolvedValue(1),
	}),
};

const mockSession = {
	id: 1,
	user_id: 1,
	...tokenObj,
	accessTokenHasExpired: vi.fn().mockReturnValue(false),
	$relatedQuery: vi.fn().mockReturnValue({
		first: vi.fn().mockResolvedValue(mockUser),
	}),
};

const mockAuth = {
	generateMfaLoginToken: vi.fn().mockResolvedValue({
		token: "mfa_token_abc",
		expiresAt: new Date(Date.now() + 600_000),
	}),
	maxMfaAttempts: 3,
};

const totpOpts = {
	serviceName: "TestApp",
	secretEncryptionKey: TEST_ENCRYPTION_KEY,
};

// ─── App builder ─────────────────────────────────────────────────────────────

function buildApp(opts: {
	userResult?: unknown;
	mfaTokenResult?: unknown;
	sessionFindOneResult?: unknown;
	recoveryCodes?: string[];
	existingRecoveryCodes?: unknown[];
} = {}) {
	const app = Fastify();

	const User = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue(mockUser),
			findById: vi.fn().mockResolvedValue(
				opts.userResult !== undefined ? opts.userResult : mockUser,
			),
		}),
		authenticate: vi.fn().mockResolvedValue(
			opts.userResult !== undefined ? opts.userResult : mockUser,
		),
	} as unknown as IUserModelStatic;

	const MfaToken = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue(mockMfaToken),
			where: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(
					opts.mfaTokenResult !== undefined ? opts.mfaTokenResult : mockMfaToken,
				),
			}),
		}),
	} as unknown as IMfaTokenModelStatic;

	const RecoveryCode = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue({}),
		}),
		generateCodes: vi.fn().mockResolvedValue(opts.recoveryCodes ?? ["code1", "code2"]),
		checkForRecoveryCodeAndConsume: vi.fn().mockResolvedValue(true),
	} as unknown as IRecoveryCodeModelStatic;

	const Session = {
		query: vi.fn().mockReturnValue({
			insert: vi.fn().mockResolvedValue({ id: 1, ...tokenObj }),
			findOne: vi.fn().mockResolvedValue(opts.sessionFindOneResult ?? mockSession),
		}),
		generateTokens: vi.fn().mockReturnValue(tokenObj),
	} as unknown as ISessionModelStatic;

	const pluginOpts: AuthFastifyPluginOptions = {
		strategy: "mfa-totp",
		auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
		models: { User, Session, MfaToken, RecoveryCode },
		totp: totpOpts,
	};

	// Override User.query for $relatedQuery on mockUser (recovery codes)
	const userWithCodes = {
		...mockUser,
		$relatedQuery: vi.fn().mockReturnValue({
			where: vi.fn().mockResolvedValue(opts.existingRecoveryCodes ?? []),
			delete: vi.fn().mockResolvedValue(1),
		}),
	};

	// For protected routes that need the authenticated user
	(Session.query as ReturnType<typeof vi.fn>).mockReturnValue({
		insert: vi.fn().mockResolvedValue({ id: 1, ...tokenObj }),
		findOne: vi.fn().mockResolvedValue({
			...mockSession,
			$relatedQuery: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(userWithCodes),
			}),
		}),
	});

	registerMfaTotpStrategy(app, pluginOpts);
	return { app, User, MfaToken, RecoveryCode, Session };
}

// ─── POST /signup ─────────────────────────────────────────────────────────────

describe("POST /signup", () => {
	it("creates a user and returns session tokens", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/signup",
			payload: {
				username: "testuser",
				email: "test@example.com",
				password: "secret",
				mobile_number: "+1234567890",
			},
		});
		expect(response.statusCode).toBe(201);
		const body = response.json();
		expect(body).toHaveProperty("access_token");
		expect(body).toHaveProperty("refresh_token");
	});
});

// ─── POST /login ──────────────────────────────────────────────────────────────

describe("POST /login", () => {
	it("returns 401 when identifier is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { password: "secret" },
		});
		expect(response.statusCode).toBe(401);
	});

	it("returns 401 when credentials are invalid", async () => {
		const { app, User } = buildApp();
		(User.authenticate as ReturnType<typeof vi.fn>).mockResolvedValue(null);
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser", password: "wrong" },
		});
		expect(response.statusCode).toBe(401);
		expect(response.json()).toMatchObject({ error: "Invalid credentials" });
	});

	it("returns session tokens when MFA is not enabled", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser", password: "secret" },
		});
		expect(response.statusCode).toBe(201);
		const body = response.json();
		// User has isUsingMFA: false, so returns tokens directly
		expect(body).toHaveProperty("access_token");
	});

	it("returns an MFA token when MFA is enabled", async () => {
		const { app, User } = buildApp();
		(User.authenticate as ReturnType<typeof vi.fn>).mockResolvedValue({
			...mockUser,
			isUsingMFA: true,
		});
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login",
			payload: { identifier: "testuser", password: "secret" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.json()).toHaveProperty("token");
		// Should NOT have access_token directly
		expect(response.json()).not.toHaveProperty("access_token");
	});
});

// ─── POST /login/mfa ──────────────────────────────────────────────────────────

describe("POST /login/mfa", () => {
	it("returns 400 when token or code is missing", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token: "mfa_token_abc" }, // no code or recovery_code
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/required/i);
	});

	it("returns 400 when MFA token is not found", async () => {
		const { app } = buildApp({ mfaTokenResult: null });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token: "bad_token", code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "MFA token not found" });
	});

	it("returns 400 when max attempts exceeded", async () => {
		const { app } = buildApp({
			mfaTokenResult: { ...mockMfaToken, number_of_attempts: 3 },
		});
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token: "mfa_token_abc", code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "Too many attempts" });
	});

	it("returns 400 when MFA token has already been used", async () => {
		const { app } = buildApp({
			mfaTokenResult: { ...mockMfaToken, used_at: new Date().toISOString() },
		});
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/login/mfa",
			payload: { token: "mfa_token_abc", code: "123456" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "MFA token has already been used" });
	});
});

// ─── POST /auth/mfa/setup (protected) ────────────────────────────────────────

describe("POST /auth/mfa/setup", () => {
	it("returns 200 with QR code data on success", async () => {
		const { app } = buildApp();
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/mfa/setup",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(200);
		expect(response.json()).toHaveProperty("qrCodeImageData");
	});
});

// ─── POST /auth/mfa/recovery-codes (protected) ───────────────────────────────

describe("POST /auth/mfa/recovery-codes", () => {
	it("returns 201 with generated recovery codes", async () => {
		const { app } = buildApp({ existingRecoveryCodes: [] });
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/mfa/recovery-codes",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(201);
		expect(response.json()).toHaveProperty("codes");
		expect(Array.isArray(response.json().codes)).toBe(true);
	});

	it("returns 400 when recovery codes already exist", async () => {
		const { app } = buildApp({
			existingRecoveryCodes: [{ id: 1, code: "existing_code" }],
		});
		await app.ready();
		const response = await app.inject({
			method: "POST",
			url: "/auth/mfa/recovery-codes",
			headers: { authorization: "Bearer test_access_token" },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json().error).toMatch(/already been generated/i);
	});
});

// ─── Strategy registration ────────────────────────────────────────────────────

describe("registerMfaTotpStrategy", () => {
	it("throws when Session model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const MfaToken = {} as unknown as IMfaTokenModelStatic;
		const RecoveryCode = {} as unknown as IRecoveryCodeModelStatic;
		expect(() =>
			registerMfaTotpStrategy(app, {
				strategy: "mfa-totp",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, MfaToken, RecoveryCode },
				totp: totpOpts,
			}),
		).toThrow("Session model is required");
	});

	it("throws when MfaToken model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const Session = {} as unknown as ISessionModelStatic;
		const RecoveryCode = {} as unknown as IRecoveryCodeModelStatic;
		expect(() =>
			registerMfaTotpStrategy(app, {
				strategy: "mfa-totp",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, Session, RecoveryCode },
				totp: totpOpts,
			}),
		).toThrow("MfaToken model is required");
	});

	it("throws when RecoveryCode model is not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const Session = {} as unknown as ISessionModelStatic;
		const MfaToken = {} as unknown as IMfaTokenModelStatic;
		expect(() =>
			registerMfaTotpStrategy(app, {
				strategy: "mfa-totp",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, Session, MfaToken },
				totp: totpOpts,
			}),
		).toThrow("RecoveryCode model is required");
	});

	it("throws when totp options are not provided", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const Session = {} as unknown as ISessionModelStatic;
		const MfaToken = {} as unknown as IMfaTokenModelStatic;
		const RecoveryCode = {} as unknown as IRecoveryCodeModelStatic;
		expect(() =>
			registerMfaTotpStrategy(app, {
				strategy: "mfa-totp",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, Session, MfaToken, RecoveryCode },
			}),
		).toThrow("totp options");
	});

	it("throws when secretEncryptionKey is invalid length", () => {
		const app = Fastify();
		const User = {} as unknown as IUserModelStatic;
		const Session = {} as unknown as ISessionModelStatic;
		const MfaToken = {} as unknown as IMfaTokenModelStatic;
		const RecoveryCode = {} as unknown as IRecoveryCodeModelStatic;
		expect(() =>
			registerMfaTotpStrategy(app, {
				strategy: "mfa-totp",
				auth: mockAuth as unknown as AuthFastifyPluginOptions["auth"],
				models: { User, Session, MfaToken, RecoveryCode },
				totp: { serviceName: "Test", secretEncryptionKey: "tooshort" },
			}),
		).toThrow("64-character hex string");
	});
});
