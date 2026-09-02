import crypto from "node:crypto";
import { db, type FakeSession, matches } from "../fakeDb.js";
import { wrapUser } from "./User.js";

function wrapSession(record: FakeSession) {
	return {
		...record,
		accessTokenHasExpired: () =>
			new Date(record.access_token_expires_at).getTime() < Date.now(),
		refreshTokenHasExpired: () =>
			new Date(record.refresh_token_expires_at).getTime() < Date.now(),
		$query() {
			return {
				patchAndFetch: async (data: Partial<FakeSession>) => {
					Object.assign(record, data);
					return wrapSession(record);
				},
				delete: async () => {
					const idx = db.sessions.indexOf(record);
					if (idx !== -1) db.sessions.splice(idx, 1);
					return 1;
				},
			};
		},
		$relatedQuery(relation: string) {
			if (relation !== "user")
				throw new Error(`Unsupported relation: ${relation}`);
			return {
				first: async () => {
					const user = db.users.find((u) => u.id === record.user_id);
					return user ? wrapUser(user) : undefined;
				},
			};
		},
	};
}

const Session = {
	query() {
		return {
			async insert(data: {
				user_id: number;
				access_token: string;
				refresh_token: string;
				access_token_expires_at: string;
				refresh_token_expires_at: string;
			}) {
				const record: FakeSession = { id: db.nextId.session++, ...data };
				db.sessions.push(record);
				return wrapSession(record);
			},
			findOne: async (criteria: Record<string, unknown>) => {
				const record = db.sessions.find((s) => matches(s, criteria));
				return record ? wrapSession(record) : undefined;
			},
			select() {
				return {
					where: async (_col: string, userId: number) =>
						db.sessions.filter((s) => s.user_id === userId),
				};
			},
			delete() {
				return {
					where: (criteria: Record<string, unknown>) => ({
						whereNot: async (notCriteria: Record<string, unknown>) => {
							const toDelete = db.sessions.filter(
								(s) => matches(s, criteria) && !matches(s, notCriteria),
							);
							for (const record of toDelete) {
								const idx = db.sessions.indexOf(record);
								if (idx !== -1) db.sessions.splice(idx, 1);
							}
							return toDelete.length;
						},
					}),
				};
			},
			where(criteria: Record<string, unknown>) {
				return {
					first: async () => {
						const record = db.sessions.find((s) => matches(s, criteria));
						return record ? wrapSession(record) : undefined;
					},
				};
			},
		};
	},
	generateTokens() {
		const id = db.nextId.session;
		const now = Date.now();
		return {
			access_token: `access_${id}_${crypto.randomBytes(4).toString("hex")}`,
			access_token_expires_at: new Date(now + 3_600_000).toISOString(),
			refresh_token: `refresh_${id}_${crypto.randomBytes(4).toString("hex")}`,
			refresh_token_expires_at: new Date(now + 86_400_000).toISOString(),
		};
	},
};

export default Session;
