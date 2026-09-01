// Dependencies
import crypto from "node:crypto";
import { authenticator } from "otplib";
import type { IRecoveryCodeModelStatic, TotpOptions } from "../types.js";

const IV_LENGTH = 12; // 12-byte IV recommended for AES-256-GCM

export type TotpCrypto = {
	encrypt(secret: string): string;
	decrypt(encryptedBase64: string): string;
};

/*
  Builds the AES-256-GCM encrypt/decrypt pair used to store TOTP secrets at
  rest, keyed by the 32-byte totp.secretEncryptionKey plugin option.
*/
export function buildTotpCrypto(opts: TotpOptions): TotpCrypto {
	const { secretEncryptionKey } = opts;
	if (!secretEncryptionKey || secretEncryptionKey.length !== 64) {
		throw new Error(
			"totp.secretEncryptionKey must be a 64-character hex string (32 bytes). " +
				"Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
		);
	}

	const KEY = Buffer.from(secretEncryptionKey, "hex");

	return {
		encrypt(secret: string): string {
			const iv = crypto.randomBytes(IV_LENGTH);
			const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
			const encrypted = Buffer.concat([
				cipher.update(secret, "utf8"),
				cipher.final(),
			]);
			const authTag = cipher.getAuthTag();
			return Buffer.concat([iv, encrypted, authTag]).toString("base64");
		},

		decrypt(encryptedBase64: string): string {
			const data = Buffer.from(encryptedBase64, "base64");
			const iv = data.subarray(0, IV_LENGTH);
			const authTag = data.subarray(data.length - 16); // GCM tag is always 16 bytes
			const encrypted = data.subarray(IV_LENGTH, data.length - 16);
			const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
			decipher.setAuthTag(authTag);
			return Buffer.concat([
				decipher.update(encrypted),
				decipher.final(),
			]).toString("utf8");
		},
	};
}

/*
  Verifies a TOTP code against a user's (already-decrypted-at-call-time)
  encrypted secret. Used by mfa-totp's '/login/mfa', '/auth/mfa/verify' and
  '/auth/mfa/disable'.
*/
export function verifyTotpCode(
	totpCrypto: TotpCrypto,
	encryptedSecret: string,
	code: string,
): boolean {
	const secret = totpCrypto.decrypt(encryptedSecret);
	return authenticator.check(code, secret);
}

/*
  Verifies (and consumes) a one-time recovery code for a user. Used by
  mfa-totp's '/login/mfa' and '/auth/mfa/disable-with-recovery-code'.
*/
export async function verifyRecoveryCode(
	RecoveryCode: IRecoveryCodeModelStatic,
	userId: string | number,
	code: string,
): Promise<boolean> {
	return await RecoveryCode.checkForRecoveryCodeAndConsume(userId, code);
}
