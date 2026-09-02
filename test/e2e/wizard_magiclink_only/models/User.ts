import { db, type FakeUser, matches } from "../fakeDb.js";
import { auth } from "../lib/auth.js";

export function wrapUser(record: FakeUser) {
	return {
		...record,
		$query() {
			return {
				patch: async (data: Partial<FakeUser>) => {
					Object.assign(record, data);
				},
			};
		},
	};
}

const User = {
	query() {
		return {
			async insert(data: {
				username: string;
				email: string;
				password: string;
			}) {
				const record: FakeUser = {
					id: db.nextId.user++,
					username: data.username,
					email: data.email,
					password: await auth.hashPassword(data.password),
				};
				db.users.push(record);
				return wrapUser(record);
			},
			where(criteriaOrCol: Record<string, unknown> | string, value?: unknown) {
				const criteria =
					typeof criteriaOrCol === "string"
						? { [criteriaOrCol]: value }
						: criteriaOrCol;
				return {
					first: async () => {
						const record = db.users.find((u) => matches(u, criteria));
						return record ? wrapUser(record) : undefined;
					},
				};
			},
			findById: async (id: number) => {
				const record = db.users.find((u) => u.id === id);
				return record ? wrapUser(record) : undefined;
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
		const record = db.users.find(
			(u) => u.username === identifier || u.email === identifier,
		);
		if (!record) return null;

		const isValid = await auth.verifyPassword(password, record.password);
		if (!isValid) return null;

		return wrapUser(record);
	},
};

export default User;
