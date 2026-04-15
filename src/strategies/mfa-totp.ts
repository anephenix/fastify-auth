import crypto from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { authenticator } from "otplib";
import qrcode from "qrcode";
import { handleError } from "../helpers/handle-error.js";
import { createAuthenticateSession } from "../middleware/authenticate.js";
import type { AuthFastifyPluginOptions, TotpOptions } from "../types.js";

// ─── TOTP secret encryption helpers ──────────────────────────────────────────

const IV_LENGTH = 12; // 12-byte IV recommended for AES-256-GCM

function buildTotpCrypto(opts: TotpOptions) {
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

// ─── Strategy ─────────────────────────────────────────────────────────────────

/**
 * Registers the TOTP (Time-based One-Time Password) MFA route set:
 *
 *   POST /signup                              – create account + immediate session
 *   POST /login                              – password auth; if MFA is on, returns
 *                                             an mfa `token` instead of a session
 *   POST /login/mfa                          – verify TOTP code or recovery code,
 *                                             exchange mfa token for a session
 *   POST /auth/mfa/recovery-codes  (protected) – generate 10 recovery codes
 *   POST /auth/mfa/setup           (protected) – generate secret + QR code
 *   POST /auth/mfa/verify          (protected) – verify a TOTP code (confirm setup)
 *   POST /auth/mfa/disable         (protected) – disable MFA with password + TOTP code
 *   POST /auth/mfa/disable-with-recovery-code (protected) – disable MFA with password + recovery code
 *
 * Required models:  User, Session, MfaToken, RecoveryCode
 * Required options: totp.serviceName, totp.secretEncryptionKey
 */
export function registerMfaTotpStrategy(
	app: FastifyInstance,
	opts: AuthFastifyPluginOptions,
): void {
	const { auth, models } = opts;
	const { User, Session, MfaToken, RecoveryCode } = models;

	if (!Session) {
		throw new Error("Session model is required for the 'mfa-totp' strategy");
	}
	if (!MfaToken) {
		throw new Error("MfaToken model is required for the 'mfa-totp' strategy");
	}
	if (!RecoveryCode) {
		throw new Error(
			"RecoveryCode model is required for the 'mfa-totp' strategy",
		);
	}
	if (!opts.totp) {
		throw new Error(
			"totp options (serviceName + secretEncryptionKey) are required for the 'mfa-totp' strategy",
		);
	}

	const { serviceName } = opts.totp;
	const totpCrypto = buildTotpCrypto(opts.totp);
	const authenticateSession = createAuthenticateSession({ Session });

	// ── POST /signup ──────────────────────────────────────────────────────────

	app.post("/signup", async (request: FastifyRequest, reply: FastifyReply) => {
		const { username, email, password, mobile_number } = request.body as {
			username: string;
			email: string;
			password: string;
			mobile_number: string;
		};

		try {
			const user = await User.query().insert({
				username,
				email,
				password,
				mobile_number,
			});

			const session = await Session.query().insert({
				user_id: user.id,
				...Session.generateTokens(),
			});

			const {
				access_token,
				refresh_token,
				access_token_expires_at,
				refresh_token_expires_at,
			} = session;

			return reply.status(201).send({
				access_token,
				refresh_token,
				access_token_expires_at,
				refresh_token_expires_at,
			});
		} catch (error) {
			reply.status(400).send({ error: handleError(error as Error) });
		}
	});

	// ── POST /login ───────────────────────────────────────────────────────────

	app.post("/login", async (request: FastifyRequest, reply: FastifyReply) => {
		try {
			const { identifier, password } = request.body as {
				identifier: string;
				password: string;
			};

			if (!identifier) {
				throw new Error("Please provide your username or email address");
			}
			if (!password) throw new Error("Password is required");

			const user = await User.authenticate({ identifier, password });
			if (!user) {
				return reply.status(401).send({ error: "Invalid credentials" });
			}

			// User.authenticate returns { id, username, isUsingMFA } for this strategy
			if (user.isUsingMFA) {
				const { token, expiresAt } = await auth.generateMfaLoginToken();

				await MfaToken.query().insert({
					user_id: user.id,
					token,
					expires_at: expiresAt.toISOString(),
					number_of_attempts: 0,
				});

				return reply.status(201).send({ token });
			}

			const session = await Session.query().insert({
				user_id: user.id,
				...Session.generateTokens(),
			});

			const {
				access_token,
				refresh_token,
				access_token_expires_at,
				refresh_token_expires_at,
			} = session;

			return reply.status(201).send({
				access_token,
				refresh_token,
				access_token_expires_at,
				refresh_token_expires_at,
			});
		} catch (error) {
			reply.status(401).send({ error: handleError(error as Error) });
		}
	});

	// ── POST /login/mfa ───────────────────────────────────────────────────────

	app.post(
		"/login/mfa",
		async (request: FastifyRequest, reply: FastifyReply) => {
			const { token, code, recovery_code } = request.body as {
				token: string;
				code?: string;
				recovery_code?: string;
			};

			if (!token || (!code && !recovery_code)) {
				return reply
					.status(400)
					.send({ error: "Token and code/recovery_code are required" });
			}

			try {
				const mfaToken = await MfaToken.query().where({ token }).first();
				if (!mfaToken) {
					return reply.status(400).send({ error: "MFA token not found" });
				}
				if (mfaToken.number_of_attempts >= auth.maxMfaAttempts) {
					return reply.status(400).send({ error: "Too many attempts" });
				}
				if (mfaToken.used_at) {
					return reply
						.status(400)
						.send({ error: "MFA token has already been used" });
				}

				const user = await User.query().findById(mfaToken.user_id);
				if (!user) {
					return reply.status(400).send({ error: "User not found" });
				}
				if (!user.mfa_totp_secret) {
					return reply
						.status(400)
						.send({ error: "User does not have MFA enabled" });
				}

				if (recovery_code) {
					const isValid = await RecoveryCode.checkForRecoveryCodeAndConsume(
						user.id,
						recovery_code,
					);
					if (!isValid) {
						return reply.status(400).send({ error: "Invalid recovery code" });
					}
				} else {
					const secret = totpCrypto.decrypt(user.mfa_totp_secret);
					const isValid = authenticator.check(code as string, secret);
					if (!isValid) {
						await mfaToken.$query().increment("number_of_attempts", 1);
						return reply.status(400).send({ error: "Invalid code" });
					}
				}

				const session = await Session.query().insert({
					user_id: mfaToken.user_id,
					...Session.generateTokens(),
				});
				await mfaToken.$query().patch({ used_at: new Date().toISOString() });

				const {
					access_token,
					refresh_token,
					access_token_expires_at,
					refresh_token_expires_at,
				} = session;

				return reply.status(201).send({
					access_token,
					refresh_token,
					access_token_expires_at,
					refresh_token_expires_at,
				});
			} catch (error) {
				reply.status(401).send({ error: handleError(error as Error) });
			}
		},
	);

	// ── POST /auth/mfa/recovery-codes (protected) ─────────────────────────────

	app.post(
		"/auth/mfa/recovery-codes",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			if (!user) return reply.status(401).send({ error: "Unauthorized" });

			const existing = await user
				.$relatedQuery("recoveryCodes")
				.where("used_at", null);

			if (existing.length > 0) {
				return reply
					.status(400)
					.send({ error: "Recovery codes have already been generated" });
			}

			const codes = await RecoveryCode.generateCodes();
			for (const code of codes) {
				await RecoveryCode.query().insert({ user_id: user.id, code });
			}

			return reply.status(201).send({ codes });
		},
	);

	// ── POST /auth/mfa/setup (protected) ──────────────────────────────────────

	app.post(
		"/auth/mfa/setup",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			if (!user) return reply.status(401).send({ error: "Unauthorized" });

			try {
				const secret = authenticator.generateSecret();
				const otpauth = authenticator.keyuri(user.email, serviceName, secret);
				const encryptedSecret = totpCrypto.encrypt(secret);

				await user.$query().patch({ mfa_totp_secret: encryptedSecret });

				const qrCodeImageData = await qrcode.toDataURL(otpauth);
				return reply.status(200).send({ qrCodeImageData });
			} catch (error) {
				reply.status(500).send({ error: handleError(error as Error) });
			}
		},
	);

	// ── POST /auth/mfa/verify (protected) ────────────────────────────────────

	app.post(
		"/auth/mfa/verify",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const { token } = request.body as { token: string };
			const user = request.user;
			if (!user) return reply.status(401).send({ error: "Unauthorized" });

			const secret = totpCrypto.decrypt(user.mfa_totp_secret);
			const isValid = authenticator.check(token, secret);

			if (!isValid) {
				return reply.status(400).send({ error: "Invalid TOTP token" });
			}
			return reply
				.status(200)
				.send({ message: "TOTP token verified successfully" });
		},
	);

	// ── POST /auth/mfa/disable (protected) ───────────────────────────────────

	app.post(
		"/auth/mfa/disable",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			const { password, code } = request.body as {
				password: string;
				code: string;
			};
			if (!user) return reply.status(401).send({ error: "Unauthorized" });

			try {
				const isPasswordValid = await User.authenticate({
					identifier: user.username,
					password,
				});
				if (!isPasswordValid) throw new Error("Invalid password");

				const secret = totpCrypto.decrypt(user.mfa_totp_secret);
				if (!authenticator.check(code, secret)) {
					throw new Error("Invalid MFA TOTP code");
				}

				await user.$query().patch({ mfa_totp_secret: null });
				await user.$relatedQuery("recoveryCodes").delete();

				return reply
					.status(200)
					.send({ message: "MFA TOTP disabled successfully" });
			} catch (error) {
				reply.status(400).send({ error: handleError(error as Error) });
			}
		},
	);

	// ── POST /auth/mfa/disable-with-recovery-code (protected) ────────────────

	app.post(
		"/auth/mfa/disable-with-recovery-code",
		{ preHandler: [authenticateSession] },
		async (request: FastifyRequest, reply: FastifyReply) => {
			const user = request.user;
			const { password, code } = request.body as {
				password: string;
				code: string;
			};
			if (!user) return reply.status(401).send({ error: "Unauthorized" });

			try {
				const isPasswordValid = await User.authenticate({
					identifier: user.username,
					password,
				});
				if (!isPasswordValid) throw new Error("Invalid password");

				const isRecoveryCodeValid =
					await RecoveryCode.checkForRecoveryCodeAndConsume(user.id, code);
				if (!isRecoveryCodeValid) throw new Error("Invalid Recovery code");

				await user.$query().patch({ mfa_totp_secret: null });
				await user.$relatedQuery("recoveryCodes").delete();

				return reply
					.status(200)
					.send({ message: "MFA TOTP disabled successfully" });
			} catch (error) {
				reply.status(400).send({ error: handleError(error as Error) });
			}
		},
	);
}
