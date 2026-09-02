export type FakeUser = {
	id: number;
	username: string;
	email: string;
	password: string;
};

export type FakeSession = {
	id: number;
	user_id: number;
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
};

export const db = {
	users: [] as FakeUser[],
	sessions: [] as FakeSession[],
	nextId: {
		user: 1,
		session: 1,
	},
};

export function matches(
	record: Record<string, unknown>,
	criteria: Record<string, unknown>,
): boolean {
	return Object.entries(criteria).every(([k, v]) => record[k] === v);
}
