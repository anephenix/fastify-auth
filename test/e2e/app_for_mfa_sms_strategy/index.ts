import { Auth } from "@anephenix/auth";
import Fastify, { type FastifyInstance } from "fastify";
import authPlugin from "../../../src/index.js";
import type {
	ISessionModelStatic,
	ISmsCodeModelStatic,
	IUserModelStatic,
} from "../../../src/types.js";

// ─── In-memory fake models ───────────────────────────────────────────────────
//
// Stand-ins for a real ORM, implementing just enough of the model interfaces
// documented in the README for the mfa-sms strategy to run against, wired
// into the real plugin (src/index.ts). Uses the real @anephenix/auth Auth
// instance for SMS code generation/hashing and session token generation,
// rather than mocking that logic.

export interface FakeUser {
	id: number;
	username: string;
	email: string;
	password: string;
}

export interface FakeSmsCode {
	id: number;
	user_id: number;
	token: string;
	hashed_code: string;
	expires_at: string;
	used_at?: string;
	codeHasExpired: () => boolean;
	verifyCode: (code: string) => Promise<boolean>;
	$query: () => { patch: (data: Partial<FakeSmsCode>) => Promise<number> };
}

export interface FakeSession {
	id: number;
	user_id: number;
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
}

export interface SentSmsCode {
	userId: number;
	token: string;
	code: string;
}

export interface BuiltApp {
	app: FastifyInstance;
	auth: Auth;
	users: FakeUser[];
	smsCodes: FakeSmsCode[];
	sessions: FakeSession[];
	sentSmsCodes: SentSmsCode[];
	addUser: (data: {
		username: string;
		email: string;
		password: string;
	}) => FakeUser;
}

export function buildApp(): BuiltApp {
	const auth = new Auth({});

	const users: FakeUser[] = [];
	const smsCodes: FakeSmsCode[] = [];
	const sessions: FakeSession[] = [];
	const sentSmsCodes: SentSmsCode[] = [];
	let nextUserId = 1;
	let nextSmsCodeId = 1;
	let nextSessionId = 1;

	function addUser(data: {
		username: string;
		email: string;
		password: string;
	}): FakeUser {
		const user: FakeUser = { id: nextUserId++, ...data };
		users.push(user);
		return user;
	}

	const User = {
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
			return user;
		},
	} as unknown as IUserModelStatic;

	const SmsCode = {
		query: () => ({
			insert: async (data: {
				user_id: number;
				token: string;
				hashed_code: string;
				expires_at: string;
			}) => {
				const record = {
					id: nextSmsCodeId++,
					user_id: data.user_id,
					token: data.token,
					hashed_code: data.hashed_code,
					expires_at: data.expires_at,
					used_at: undefined,
				} as FakeSmsCode;
				record.codeHasExpired = () =>
					new Date(record.expires_at).getTime() < Date.now();
				record.verifyCode = (code: string) =>
					auth.verifyPassword(code, record.hashed_code);
				record.$query = () => ({
					patch: async (patchData: Partial<FakeSmsCode>) => {
						Object.assign(record, patchData);
						return 1;
					},
				});
				smsCodes.push(record);
				return record;
			},
			findOne: async ({ token }: { token: string }) =>
				smsCodes.find((record) => record.token === token),
		}),
	} as unknown as ISmsCodeModelStatic;

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
		}),
		generateTokens: () => {
			const generated = auth.generateSession();
			return {
				access_token: generated.accessToken,
				access_token_expires_at: generated.accessTokenExpiresAt.toISOString(),
				refresh_token: generated.refreshToken,
				refresh_token_expires_at: generated.refreshTokenExpiresAt.toISOString(),
			};
		},
	} as unknown as ISessionModelStatic;

	const app = Fastify();
	app.register(authPlugin, {
		strategy: "mfa-sms",
		auth,
		models: { User, Session, SmsCode },
		hooks: {
			onSmsCodeCreated: async ({ user, token, code }) => {
				sentSmsCodes.push({ userId: user.id, token, code });
			},
		},
	});

	return { app, auth, users, smsCodes, sessions, sentSmsCodes, addUser };
}
