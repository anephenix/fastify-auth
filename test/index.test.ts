import { describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import authPlugin from "../src/index.js";
import type {
	AuthFastifyPluginOptions,
	IForgotPasswordModelStatic,
	IMagicLinkModelStatic,
	IMfaTokenModelStatic,
	IRecoveryCodeModelStatic,
	ISessionModelStatic,
	IUserModelStatic,
} from "../src/types.js";

vi.mock("otplib", () => ({
	authenticator: {
		generateSecret: vi.fn().mockReturnValue("TESTSECRET"),
		keyuri: vi.fn().mockReturnValue("otpauth://totp/test"),
		check: vi.fn().mockReturnValue(true),
	},
}));

vi.mock("qrcode", () => ({
	default: {
		toDataURL: vi.fn().mockResolvedValue("data:image/png;base64,test"),
	},
}));

const TEST_ENCRYPTION_KEY =
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const mockAuth = {
	accessTokenExpiresIn: 3600,
	refreshTokenExpiresIn: 86400,
	generateMfaLoginToken: vi.fn(),
	generateSmsCode: vi.fn(),
	maxMfaAttempts: 3,
	normalize: vi.fn().mockImplementation((s: string) => s),
	validatePassword: vi.fn().mockReturnValue(true),
	verifyPassword: vi.fn().mockResolvedValue(true),
} as unknown as AuthFastifyPluginOptions["auth"];

const User = {} as unknown as IUserModelStatic;
const Session = {} as unknown as ISessionModelStatic;
const MagicLink = {} as unknown as IMagicLinkModelStatic;
const MfaToken = {} as unknown as IMfaTokenModelStatic;
const RecoveryCode = {} as unknown as IRecoveryCodeModelStatic;
const ForgotPassword = {} as unknown as IForgotPasswordModelStatic;

describe("authPlugin (index.ts)", () => {
	it("registers the sessions strategy successfully", async () => {
		const app = Fastify();
		await app.register(authPlugin, {
			strategy: "sessions",
			auth: mockAuth,
			models: { User, Session },
		});
		await app.ready();
		// Verify the /signup route was registered
		const response = await app.inject({ method: "POST", url: "/signup" });
		// Will get a 400 (bad input) not a 404, confirming route exists
		expect(response.statusCode).not.toBe(404);
	});

	it("registers the magic-links strategy successfully", async () => {
		const app = Fastify();
		await app.register(authPlugin, {
			strategy: "magic-links",
			auth: mockAuth,
			models: { User, Session, MagicLink },
		});
		await app.ready();
		const response = await app.inject({ method: "POST", url: "/magic-links" });
		expect(response.statusCode).not.toBe(404);
	});

	it("registers the mfa-sms strategy successfully", async () => {
		const app = Fastify();
		await app.register(authPlugin, {
			strategy: "mfa-sms",
			auth: mockAuth,
			models: { User, Session, SmsCode: {} as never },
		});
		await app.ready();
		const response = await app.inject({ method: "POST", url: "/sessions" });
		expect(response.statusCode).not.toBe(404);
	});

	it("registers the mfa-totp strategy successfully", async () => {
		const app = Fastify();
		await app.register(authPlugin, {
			strategy: "mfa-totp",
			auth: mockAuth,
			models: { User, Session, MfaToken, RecoveryCode },
			totp: { serviceName: "TestApp", secretEncryptionKey: TEST_ENCRYPTION_KEY },
		});
		await app.ready();
		const response = await app.inject({ method: "POST", url: "/signup" });
		expect(response.statusCode).not.toBe(404);
	});

	it("registers the forgotten-password strategy successfully", async () => {
		const app = Fastify();
		await app.register(authPlugin, {
			strategy: "forgotten-password",
			auth: mockAuth,
			models: { User, ForgotPassword },
		});
		await app.ready();
		const response = await app.inject({ method: "POST", url: "/forgot-password" });
		expect(response.statusCode).not.toBe(404);
	});

	it("throws for an unknown strategy", async () => {
		const app = Fastify();
		await expect(
			app.register(authPlugin, {
				strategy: "unknown-strategy" as never,
				auth: mockAuth,
				models: { User },
			}),
		).rejects.toThrow(/Unknown strategy/);
	});
});
