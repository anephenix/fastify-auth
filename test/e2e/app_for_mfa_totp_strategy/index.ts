import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Auth } from "@anephenix/auth";
import Fastify, { type FastifyInstance } from "fastify";
import authPlugin from "../../../src/index.js";
import type {
	IMfaTokenModelStatic,
	IRecoveryCodeModelStatic,
	ISessionModelStatic,
	IUserModelStatic,
} from "../../../src/types.js";

// ─── TOTP secret encryption (test-side) ──────────────────────────────────────
//
// Mirrors src/strategies/mfa-totp.ts's AES-256-GCM scheme, using the same key
// this test app configures the plugin with. The API never exposes a raw TOTP
// secret (only a QR code image encoding it), so tests use this to seed users
// with a known secret directly, and to recover whatever secret the real
// /auth/mfa/setup route encrypted, without needing to decode a QR image.

export const TOTP_SECRET_ENCRYPTION_KEY =
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const IV_LENGTH = 12;
const KEY = Buffer.from(TOTP_SECRET_ENCRYPTION_KEY, "hex");

export function encryptTotpSecret(secret: string): string {
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv("aes-256-gcm", KEY, iv);
	const encrypted = Buffer.concat([
		cipher.update(secret, "utf8"),
		cipher.final(),
	]);
	const authTag = cipher.getAuthTag();
	return Buffer.concat([iv, encrypted, authTag]).toString("base64");
}

export function decryptTotpSecret(encryptedBase64: string): string {
	const data = Buffer.from(encryptedBase64, "base64");
	const iv = data.subarray(0, IV_LENGTH);
	const authTag = data.subarray(data.length - 16);
	const encrypted = data.subarray(IV_LENGTH, data.length - 16);
	const decipher = createDecipheriv("aes-256-gcm", KEY, iv);
	decipher.setAuthTag(authTag);
	return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
		"utf8",
	);
}

// ─── In-memory fake models ───────────────────────────────────────────────────
//
// Stand-ins for a real ORM, implementing just enough of the model interfaces
// documented in the README for the mfa-totp strategy to run against, wired
// into the real plugin. Uses the real @anephenix/auth Auth instance and the
// real otplib/qrcode dependencies (both real deps of this library already)
// rather than mocking them.

export interface FakeRecoveryCode {
	id: number;
	user_id: number;
	hashed_code: string;
	used_at?: string;
}

export interface FakeUser {
	id: number;
	username: string;
	email: string;
	password: string;
	mobile_number?: string;
	mfa_totp_secret: string | null;
	$query: () => { patch: (data: Partial<FakeUser>) => Promise<number> };
	$relatedQuery: (relation: string) => {
		where: (column: string, value: unknown) => Promise<FakeRecoveryCode[]>;
		delete: () => Promise<number>;
	};
}

export interface FakeMfaToken {
	id: number;
	user_id: number;
	token: string;
	expires_at: string;
	used_at?: string;
	number_of_attempts: number;
	$query: () => {
		patch: (data: Partial<FakeMfaToken>) => Promise<number>;
		increment: (field: string, amount: number) => Promise<number>;
	};
}

export interface FakeSession {
	id: number;
	user_id: number;
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
}

export interface BuiltApp {
	app: FastifyInstance;
	auth: Auth;
	users: FakeUser[];
	sessions: FakeSession[];
	mfaTokens: FakeMfaToken[];
	recoveryCodes: FakeRecoveryCode[];
	addUser: (data: {
		username: string;
		email: string;
		password: string;
		mobile_number?: string;
		mfa_totp_secret?: string | null;
	}) => FakeUser;
	createSession: (userId: number) => FakeSession;
}

export function buildApp(): BuiltApp {
	const auth = new Auth({});

	const users: FakeUser[] = [];
	const sessions: FakeSession[] = [];
	const mfaTokens: FakeMfaToken[] = [];
	const recoveryCodes: FakeRecoveryCode[] = [];
	let nextUserId = 1;
	let nextSessionId = 1;
	let nextMfaTokenId = 1;
	let nextRecoveryCodeId = 1;

	function generateSessionTokens() {
		const generated = auth.generateSession();
		return {
			access_token: generated.accessToken,
			access_token_expires_at: generated.accessTokenExpiresAt.toISOString(),
			refresh_token: generated.refreshToken,
			refresh_token_expires_at: generated.refreshTokenExpiresAt.toISOString(),
		};
	}

	function addUser(data: {
		username: string;
		email: string;
		password: string;
		mobile_number?: string;
		mfa_totp_secret?: string | null;
	}): FakeUser {
		const user = {
			id: nextUserId++,
			username: data.username,
			email: data.email,
			password: data.password,
			mobile_number: data.mobile_number,
			mfa_totp_secret: data.mfa_totp_secret ?? null,
		} as FakeUser;
		user.$query = () => ({
			patch: async (patchData: Partial<FakeUser>) => {
				Object.assign(user, patchData);
				return 1;
			},
		});
		user.$relatedQuery = (relation: string) => {
			if (relation !== "recoveryCodes") {
				throw new Error(`Unsupported relation: ${relation}`);
			}
			return {
				// `value == null` groups `null`/`undefined` together, matching how a
				// real DB's NULL column reads back as `undefined` on an in-memory
				// object that never set the field, e.g. `.where("used_at", null)`.
				where: async (column: string, value: unknown) =>
					recoveryCodes.filter((rc) => {
						if (rc.user_id !== user.id) return false;
						const actual = (rc as unknown as Record<string, unknown>)[column];
						return value == null ? actual == null : actual === value;
					}),
				delete: async () => {
					const before = recoveryCodes.length;
					for (let i = recoveryCodes.length - 1; i >= 0; i--) {
						if (recoveryCodes[i].user_id === user.id)
							recoveryCodes.splice(i, 1);
					}
					return before - recoveryCodes.length;
				},
			};
		};
		users.push(user);
		return user;
	}

	function createSession(userId: number): FakeSession {
		const record: FakeSession = {
			id: nextSessionId++,
			user_id: userId,
			...generateSessionTokens(),
		};
		sessions.push(record);
		return record;
	}

	const User = {
		query: () => ({
			insert: async (data: {
				username?: string;
				email?: string;
				password?: string;
				mobile_number?: string;
			}) => {
				const missing = (
					["username", "email", "password", "mobile_number"] as const
				).filter((field) => !data[field]);
				if (missing.length) {
					throw new Error(
						`${missing.join(", ")} ${missing.length > 1 ? "are" : "is"} required`,
					);
				}
				return addUser(
					data as {
						username: string;
						email: string;
						password: string;
						mobile_number: string;
					},
				);
			},
			findById: async (id: number) => users.find((user) => user.id === id),
		}),
		async authenticate({
			identifier,
			password,
		}: {
			identifier: string;
			password: string;
		}) {
			const user = users.find(
				(candidate) =>
					candidate.username === identifier || candidate.email === identifier,
			);
			if (!user || user.password !== password) return null;
			return { ...user, isUsingMFA: !!user.mfa_totp_secret };
		},
	} as unknown as IUserModelStatic;

	const Session = {
		query: () => ({
			insert: async (data: {
				user_id: number;
				access_token: string;
				refresh_token: string;
				access_token_expires_at: string;
				refresh_token_expires_at: string;
			}) => {
				const record: FakeSession = { id: nextSessionId++, ...data };
				sessions.push(record);
				return record;
			},
			findOne: async ({ access_token }: { access_token: string }) => {
				const record = sessions.find((s) => s.access_token === access_token);
				if (!record) return undefined;
				return {
					...record,
					accessTokenHasExpired: () =>
						new Date(record.access_token_expires_at).getTime() < Date.now(),
					$relatedQuery: (relation: string) => {
						if (relation !== "user") {
							throw new Error(`Unsupported relation: ${relation}`);
						}
						return {
							first: async () => users.find((u) => u.id === record.user_id),
						};
					},
				};
			},
		}),
		generateTokens: generateSessionTokens,
	} as unknown as ISessionModelStatic;

	const MfaToken = {
		query: () => ({
			insert: async (data: {
				user_id: number;
				token: string;
				expires_at: string;
				number_of_attempts: number;
			}) => {
				const record = { id: nextMfaTokenId++, ...data } as FakeMfaToken;
				record.$query = () => ({
					patch: async (patchData: Partial<FakeMfaToken>) => {
						Object.assign(record, patchData);
						return 1;
					},
					increment: async (field: string, amount: number) => {
						const key = field as keyof FakeMfaToken;
						(record[key] as number) = ((record[key] as number) ?? 0) + amount;
						return 1;
					},
				});
				mfaTokens.push(record);
				return record;
			},
			where: (criteria: Record<string, unknown>) => ({
				first: async () =>
					mfaTokens.find((record) =>
						Object.entries(criteria).every(
							([key, value]) =>
								(record as unknown as Record<string, unknown>)[key] === value,
						),
					),
			}),
		}),
	} as unknown as IMfaTokenModelStatic;

	const RecoveryCode = {
		query: () => ({
			insert: async (data: { user_id: number; code: string }) => {
				const hashed_code = await auth.hashPassword(data.code);
				const record: FakeRecoveryCode = {
					id: nextRecoveryCodeId++,
					user_id: data.user_id,
					hashed_code,
					used_at: undefined,
				};
				recoveryCodes.push(record);
				return record;
			},
		}),
		generateCodes: async () =>
			Array.from({ length: 10 }, () => randomBytes(5).toString("hex")),
		checkForRecoveryCodeAndConsume: async (userId: number, code: string) => {
			const candidates = recoveryCodes.filter(
				(rc) => rc.user_id === userId && !rc.used_at,
			);
			for (const candidate of candidates) {
				if (await auth.verifyPassword(code, candidate.hashed_code)) {
					candidate.used_at = new Date().toISOString();
					return true;
				}
			}
			return false;
		},
	} as unknown as IRecoveryCodeModelStatic;

	const app = Fastify();
	app.register(authPlugin, {
		strategy: "mfa-totp",
		auth,
		models: { User, Session, MfaToken, RecoveryCode },
		totp: {
			serviceName: "TestApp",
			secretEncryptionKey: TOTP_SECRET_ENCRYPTION_KEY,
		},
	});

	return {
		app,
		auth,
		users,
		sessions,
		mfaTokens,
		recoveryCodes,
		addUser,
		createSession,
	};
}
