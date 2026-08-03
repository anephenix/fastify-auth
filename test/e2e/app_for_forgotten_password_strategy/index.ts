import { Auth } from "@anephenix/auth";
import Fastify, { type FastifyInstance } from "fastify";
import authPlugin from "../../../src/index.js";
import type {
	IForgotPasswordModelStatic,
	IUserModelStatic,
} from "../../../src/types.js";

// ─── In-memory fake models ───────────────────────────────────────────────────
//
// Stand-ins for a real ORM, implementing just enough of the model interfaces
// documented in the README for the forgotten-password strategy to run
// against. The forgotten-password strategy never touches the ForgotPassword
// model itself beyond looking records up — creating them is entirely
// delegated to `hooks.onForgotPasswordRequested`, so this file also plays
// the role of "the consuming app" by implementing that hook the way the
// README's example does, using the real @anephenix/auth Auth instance for
// token generation and hashing.

export interface FakeUser {
	id: number;
	username: string;
	email: string;
	password: string;
	updatePassword: (password: string) => Promise<void>;
}

export interface FakeForgotPasswordRecord {
	id: number;
	user_id: number;
	selector: string;
	token_hash: string;
	expires_at: Date;
	used_at: Date | null;
	markAsUsed: () => Promise<void>;
}

export interface SentReset {
	identifier: string;
	isEmail: boolean;
	userId?: number;
	selector?: string;
	token?: string;
}

export interface BuiltApp {
	app: FastifyInstance;
	auth: Auth;
	users: FakeUser[];
	forgotPasswordRecords: FakeForgotPasswordRecord[];
	sentResets: SentReset[];
	addUser: (data: {
		username: string;
		email: string;
		password: string;
	}) => FakeUser;
}

export function buildApp(): BuiltApp {
	const auth = new Auth({ passwordValidationRules: { minLength: 8 } });

	const users: FakeUser[] = [];
	const forgotPasswordRecords: FakeForgotPasswordRecord[] = [];
	const sentResets: SentReset[] = [];
	let nextUserId = 1;
	let nextRecordId = 1;

	function addUser(data: {
		username: string;
		email: string;
		password: string;
	}): FakeUser {
		const user: FakeUser = {
			id: nextUserId++,
			...data,
			updatePassword: async (password: string) => {
				user.password = password;
			},
		};
		users.push(user);
		return user;
	}

	async function createRecordForUser(userId: number) {
		const selector = auth.tokenGenerator();
		const token = auth.tokenGenerator();
		const token_hash = await auth.hashPassword(token);
		const record: FakeForgotPasswordRecord = {
			id: nextRecordId++,
			user_id: userId,
			selector,
			token_hash,
			expires_at: new Date(Date.now() + 3_600_000),
			used_at: null,
			markAsUsed: async () => {
				record.used_at = new Date();
			},
		};
		forgotPasswordRecords.push(record);
		return { record, token };
	}

	const User = {
		query: () => ({
			findById: async (id: number) => users.find((user) => user.id === id),
		}),
	} as unknown as IUserModelStatic;

	const ForgotPassword = {
		query: () => ({
			where: (column: string, value: unknown) => ({
				first: async () =>
					forgotPasswordRecords.find(
						(record) =>
							(record as unknown as Record<string, unknown>)[column] === value,
					),
			}),
		}),
	} as unknown as IForgotPasswordModelStatic;

	const app = Fastify();
	app.register(authPlugin, {
		strategy: "forgotten-password",
		auth,
		models: { User, ForgotPassword },
		hooks: {
			onForgotPasswordRequested: async ({ identifier, isEmail }) => {
				const user = users.find((candidate) =>
					isEmail
						? candidate.email === identifier
						: candidate.username === identifier,
				);
				if (!user) {
					sentResets.push({ identifier, isEmail });
					return;
				}
				const { record, token } = await createRecordForUser(user.id);
				sentResets.push({
					identifier,
					isEmail,
					userId: user.id,
					selector: record.selector,
					token,
				});
			},
		},
	});

	return { app, auth, users, forgotPasswordRecords, sentResets, addUser };
}
