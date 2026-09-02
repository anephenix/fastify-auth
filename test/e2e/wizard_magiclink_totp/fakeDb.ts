export type FakeUser = {
	id: number;
	username: string;
	email: string;
	password: string;
	mfa_totp_secret: string | null;
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

export type FakeMfaToken = {
	id: number;
	user_id: number;
	token: string;
	expires_at: string;
	used_at: string | null;
	number_of_attempts: number;
};

export type FakeRecoveryCode = {
	id: number;
	user_id: number;
	hashed_code: string;
	used_at: string | null;
};

export const db = {
	users: [] as FakeUser[],
	sessions: [] as FakeSession[],
	magicLinks: [] as FakeMagicLink[],
	mfaTokens: [] as FakeMfaToken[],
	recoveryCodes: [] as FakeRecoveryCode[],
	nextId: {
		user: 1,
		session: 1,
		magicLink: 1,
		mfaToken: 1,
		recoveryCode: 1,
	},
};

export function matches(
	record: Record<string, unknown>,
	criteria: Record<string, unknown>,
): boolean {
	return Object.entries(criteria).every(([k, v]) => record[k] === v);
}
