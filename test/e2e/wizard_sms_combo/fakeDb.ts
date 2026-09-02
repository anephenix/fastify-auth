/*
  A shared in-memory "database" for the wizard e2e fixtures - avoids
  circular imports between the fake model files (they all import this
  instead of importing each other), and lets the test assert on state
  directly (e.g. that a magic link was marked used).
*/

export type FakeUser = {
	id: number;
	username: string;
	email: string;
	password: string;
	sms_mfa_enabled: boolean;
	mobile_number: string | null;
};

export type FakeSession = {
	id: number;
	user_id: number;
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
};

export type FakeMagicLink = {
	id: number;
	user_id: number;
	token: string;
	hashed_code: string;
	expires_at: string;
	used_at: string | null;
};

export type FakeSmsCode = {
	id: number;
	user_id: number;
	token: string;
	hashed_code: string;
	expires_at: string;
	used_at: string | null;
};

export type FakeForgotPassword = {
	id: number;
	user_id: number;
	selector: string;
	token_hash: string;
	expires_at: Date;
	used_at: Date | null;
};

export const db = {
	users: [] as FakeUser[],
	sessions: [] as FakeSession[],
	magicLinks: [] as FakeMagicLink[],
	smsCodes: [] as FakeSmsCode[],
	forgotPasswords: [] as FakeForgotPassword[],
	nextId: {
		user: 1,
		session: 1,
		magicLink: 1,
		smsCode: 1,
		forgotPassword: 1,
	},
};

export function matches(
	record: Record<string, unknown>,
	criteria: Record<string, unknown>,
): boolean {
	return Object.entries(criteria).every(([k, v]) => record[k] === v);
}
