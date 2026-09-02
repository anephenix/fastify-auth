import type { Auth } from "@anephenix/auth";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import authPlugin from "../../../src/index.js";
import type {
	ISessionModel,
	ISessionModelStatic,
	IUserModel,
	IUserModelStatic,
} from "../../../src/types.js";

// ─── In-memory fake models ───────────────────────────────────────────────────
//
// Stand-ins for a real ORM (e.g. Objection.js), implementing just enough of
// the model interfaces documented in the README for the sessions strategy to
// run against. This lets the e2e tests exercise the full plugin — real HTTP
// requests through the real route handlers backed by a real persistence
// layer — without needing a database.

export interface FakeUser extends IUserModel {
	password: string;
}

export class SessionRecord implements ISessionModel {
	id: number;
	user_id: number;
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
	user_agent?: string;
	ip_address?: string;

	private readonly users: FakeUser[];
	private readonly sessions: SessionRecord[];

	constructor(
		data: {
			id: number;
			user_id: number;
			access_token: string;
			refresh_token: string;
			access_token_expires_at: string;
			refresh_token_expires_at: string;
		},
		users: FakeUser[],
		sessions: SessionRecord[],
	) {
		this.id = data.id;
		this.user_id = data.user_id;
		this.access_token = data.access_token;
		this.refresh_token = data.refresh_token;
		this.access_token_expires_at = data.access_token_expires_at;
		this.refresh_token_expires_at = data.refresh_token_expires_at;
		this.users = users;
		this.sessions = sessions;
	}

	accessTokenHasExpired(): boolean {
		return new Date(this.access_token_expires_at).getTime() < Date.now();
	}

	refreshTokenHasExpired(): boolean {
		return new Date(this.refresh_token_expires_at).getTime() < Date.now();
	}

	$relatedQuery(relation: string) {
		if (relation !== "user") {
			throw new Error(`Unsupported relation: ${relation}`);
		}
		return {
			first: async () => this.users.find((user) => user.id === this.user_id),
		};
	}

	$query() {
		return {
			patchAndFetch: async (data: Partial<SessionRecord>) => {
				Object.assign(this, data);
				return this;
			},
			delete: async () => {
				const index = this.sessions.indexOf(this);
				if (index !== -1) this.sessions.splice(index, 1);
				return 1;
			},
		};
	}
}

type QueryMode = "select" | "delete";

// Route params (e.g. `:id`) arrive as strings; a real integer column would
// coerce "1" to 1 at the DB layer, so mimic that here.
function matches(actual: unknown, expected: unknown): boolean {
	if (typeof actual === "number" || typeof expected === "number") {
		return String(actual) === String(expected);
	}
	return actual === expected;
}

/**
 * Mimics just enough of Objection.js's thenable QueryBuilder (where/whereNot/
 * select/first/findOne/delete, awaitable at any point in the chain) to satisfy
 * the call patterns used in src/strategies/sessions.ts and
 * src/middleware/authenticate.ts.
 */
class SessionQueryBuilder {
	private rows: SessionRecord[];
	private mode: QueryMode = "select";
	private cols?: string[];
	private single = false;

	constructor(
		private readonly sessions: SessionRecord[],
		private readonly users: FakeUser[],
		private readonly nextId: () => number,
	) {
		this.rows = sessions;
	}

	where(criteriaOrCol: string | Record<string, unknown>, value?: unknown) {
		const match =
			typeof criteriaOrCol === "string"
				? { [criteriaOrCol]: value }
				: criteriaOrCol;
		this.rows = this.rows.filter((row) =>
			Object.entries(match).every(([key, val]) =>
				matches((row as unknown as Record<string, unknown>)[key], val),
			),
		);
		return this;
	}

	whereNot(criteria: Record<string, unknown>) {
		this.rows = this.rows.filter(
			(row) =>
				!Object.entries(criteria).every(([key, val]) =>
					matches((row as unknown as Record<string, unknown>)[key], val),
				),
		);
		return this;
	}

	select(...cols: string[]) {
		this.cols = cols;
		return this;
	}

	first() {
		this.single = true;
		return this;
	}

	findOne(criteria: Record<string, unknown>) {
		this.where(criteria);
		this.single = true;
		return this;
	}

	delete() {
		this.mode = "delete";
		return this;
	}

	insert(data: {
		user_id: number;
		access_token: string;
		refresh_token: string;
		access_token_expires_at: string;
		refresh_token_expires_at: string;
	}) {
		const record = new SessionRecord(
			{ id: this.nextId(), ...data },
			this.users,
			this.sessions,
		);
		this.sessions.push(record);
		return Promise.resolve(record);
	}

	private project(row: SessionRecord) {
		if (!this.cols?.length) return row;
		const out: Record<string, unknown> = {};
		for (const col of this.cols) {
			out[col] = (row as unknown as Record<string, unknown>)[col];
		}
		return out;
	}

	private async resolve() {
		if (this.mode === "delete") {
			const toDelete = new Set(this.rows);
			const deletedCount = toDelete.size;
			for (const row of [...this.sessions]) {
				if (toDelete.has(row)) {
					const index = this.sessions.indexOf(row);
					if (index !== -1) this.sessions.splice(index, 1);
				}
			}
			return deletedCount;
		}
		if (this.single) {
			const row = this.rows[0];
			return row ? this.project(row) : undefined;
		}
		return this.rows.map((row) => this.project(row));
	}

	// Makes the builder awaitable at any point in the chain, e.g.
	// `await Session.query().select(...).where(...)`.
	// biome-ignore lint/suspicious/noThenProperty: intentionally mimics Objection.js's thenable QueryBuilder
	then<TResult1 = unknown, TResult2 = never>(
		onFulfilled?: ((value: unknown) => TResult1 | PromiseLike<TResult1>) | null,
		onRejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
	): Promise<TResult1 | TResult2> {
		return this.resolve().then(onFulfilled, onRejected);
	}
}

export interface BuiltApp {
	app: FastifyInstance;
	users: FakeUser[];
	sessions: SessionRecord[];
}

const mockAuth = {
	accessTokenExpiresIn: 3600,
	refreshTokenExpiresIn: 86400,
} as unknown as Auth;

export function buildApp(): BuiltApp {
	const users: FakeUser[] = [];
	const sessions: SessionRecord[] = [];
	let nextUserId = 1;
	let nextSessionId = 1;

	const User = {
		query() {
			return {
				insert(data: Partial<FakeUser>) {
					const missing = (["username", "email", "password"] as const).filter(
						(field) => !data[field],
					);
					if (missing.length) {
						return Promise.reject(
							new Error(
								`${missing.join(", ")} ${missing.length > 1 ? "are" : "is"} required`,
							),
						);
					}
					if (users.some((user) => user.email === data.email)) {
						const error = Object.assign(new Error("unique violation"), {
							columns: ["email"],
						});
						Object.defineProperty(error, "constructor", {
							value: { name: "UniqueViolationError" },
						});
						return Promise.reject(error);
					}
					const user = {
						id: nextUserId++,
						username: data.username,
						email: data.email,
						password: data.password,
						...(data.mobile_number && { mobile_number: data.mobile_number }),
					} as FakeUser;
					users.push(user);
					return Promise.resolve(user);
				},
			};
		},
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

	const Session = {
		query: () =>
			new SessionQueryBuilder(sessions, users, () => nextSessionId++),
		generateTokens() {
			const now = Date.now();
			const id = nextSessionId;
			return {
				access_token: `access_${id}_${Math.random().toString(36).slice(2)}`,
				access_token_expires_at: new Date(now + 3_600_000).toISOString(),
				refresh_token: `refresh_${id}_${Math.random().toString(36).slice(2)}`,
				refresh_token_expires_at: new Date(now + 86_400_000).toISOString(),
			};
		},
	} as unknown as ISessionModelStatic;

	const app = Fastify();
	app.register(cookie);
	app.register(authPlugin, {
		strategy: "sessions",
		auth: mockAuth,
		models: { User, Session },
	});

	return { app, users, sessions };
}
