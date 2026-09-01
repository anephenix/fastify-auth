import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { authenticator } from "otplib";
import qrcode from "qrcode";
import { issueMfaChallenge } from "../core/mfa-gate.js";
import { verifyPassword } from "../core/password.js";
import { createSession } from "../core/session.js";
import {
	buildTotpCrypto,
	verifyRecoveryCode,
	verifyTotpCode,
} from "../core/totp.js";
import { handleError } from "../helpers/handle-error.js";
import { createAuthenticateSession } from "../middleware/authenticate.js";
import type { AuthFastifyPluginOptions } from "../types.js";

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

			const tokens = await createSession(Session, user.id);
			return reply.status(201).send(tokens);
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

			const user = await verifyPassword(User, identifier, password);
			if (!user) {
				return reply.status(401).send({ error: "Invalid credentials" });
			}

			// User.authenticate returns { id, username, isUsingMFA } for this strategy
			if (user.isUsingMFA) {
				const challenge = await issueMfaChallenge(MfaToken, auth, user.id);
				return reply.status(201).send(challenge);
			}

			const tokens = await createSession(Session, user.id);
			return reply.status(201).send(tokens);
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
					const isValid = await verifyRecoveryCode(
						RecoveryCode,
						user.id,
						recovery_code,
					);
					if (!isValid) {
						return reply.status(400).send({ error: "Invalid recovery code" });
					}
				} else {
					const isValid = verifyTotpCode(
						totpCrypto,
						user.mfa_totp_secret,
						code as string,
					);
					if (!isValid) {
						await mfaToken.$query().increment("number_of_attempts", 1);
						return reply.status(400).send({ error: "Invalid code" });
					}
				}

				const tokens = await createSession(Session, mfaToken.user_id);
				await mfaToken.$query().patch({ used_at: new Date().toISOString() });

				return reply.status(201).send(tokens);
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

			const isValid = verifyTotpCode(totpCrypto, user.mfa_totp_secret, token);

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

				if (!verifyTotpCode(totpCrypto, user.mfa_totp_secret, code)) {
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

				const isRecoveryCodeValid = await verifyRecoveryCode(
					RecoveryCode,
					user.id,
					code,
				);
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
