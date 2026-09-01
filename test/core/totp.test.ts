import crypto from "node:crypto";
import { authenticator } from "otplib";
import { describe, expect, it, vi } from "vitest";
import {
	buildTotpCrypto,
	verifyRecoveryCode,
	verifyTotpCode,
} from "../../src/core/totp.js";
import type { IRecoveryCodeModelStatic } from "../../src/types.js";

// ─── Mocks ────────────────────────────────────────────────────────────────────

vi.mock("otplib", () => ({
	authenticator: {
		check: vi.fn(),
	},
}));

// A valid 64-character hex key for AES-256-GCM encryption
const TEST_ENCRYPTION_KEY = crypto.randomBytes(32).toString("hex");

describe("buildTotpCrypto", () => {
	it("throws when secretEncryptionKey is missing or the wrong length", () => {
		expect(() =>
			buildTotpCrypto({ serviceName: "Test", secretEncryptionKey: "" }),
		).toThrow(/64-character hex string/);
		expect(() =>
			buildTotpCrypto({ serviceName: "Test", secretEncryptionKey: "tooshort" }),
		).toThrow(/64-character hex string/);
	});

	it("round-trips a secret through encrypt/decrypt", () => {
		const totpCrypto = buildTotpCrypto({
			serviceName: "Test",
			secretEncryptionKey: TEST_ENCRYPTION_KEY,
		});
		const encrypted = totpCrypto.encrypt("my-totp-secret");
		expect(encrypted).not.toBe("my-totp-secret");
		expect(totpCrypto.decrypt(encrypted)).toBe("my-totp-secret");
	});
});

describe("verifyTotpCode", () => {
	it("decrypts the stored secret and checks the code via otplib", () => {
		const totpCrypto = buildTotpCrypto({
			serviceName: "Test",
			secretEncryptionKey: TEST_ENCRYPTION_KEY,
		});
		const encrypted = totpCrypto.encrypt("my-totp-secret");
		vi.mocked(authenticator.check).mockReturnValue(true);

		const result = verifyTotpCode(totpCrypto, encrypted, "123456");

		expect(authenticator.check).toHaveBeenCalledWith(
			"123456",
			"my-totp-secret",
		);
		expect(result).toBe(true);
	});

	it("returns false when otplib reports an invalid code", () => {
		const totpCrypto = buildTotpCrypto({
			serviceName: "Test",
			secretEncryptionKey: TEST_ENCRYPTION_KEY,
		});
		const encrypted = totpCrypto.encrypt("my-totp-secret");
		vi.mocked(authenticator.check).mockReturnValue(false);

		expect(verifyTotpCode(totpCrypto, encrypted, "000000")).toBe(false);
	});
});

describe("verifyRecoveryCode", () => {
	it("delegates to RecoveryCode.checkForRecoveryCodeAndConsume", async () => {
		const checkForRecoveryCodeAndConsume = vi.fn().mockResolvedValue(true);
		const RecoveryCode = {
			checkForRecoveryCodeAndConsume,
		} as unknown as IRecoveryCodeModelStatic;

		const result = await verifyRecoveryCode(RecoveryCode, 42, "ABCD-1234");

		expect(checkForRecoveryCodeAndConsume).toHaveBeenCalledWith(
			42,
			"ABCD-1234",
		);
		expect(result).toBe(true);
	});
});
