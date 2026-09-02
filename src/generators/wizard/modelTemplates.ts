import type { WizardSelections } from "./types.js";

/*
  These model templates are real Objection.js model stubs (not vanilla/
  dependency-free like fastify-resource's generator) - they call back into
  @anephenix/fastify-auth's shared `auth` instance (see authLibTemplate.ts)
  for password hashing/verification, since that's the same security-
  sensitive logic the library's own strategies use.
*/

export function userModelTemplate({
	mfa,
	forgotPassword,
}: WizardSelections): string {
	const mfaField =
		mfa === "totp"
			? "\n\tmfa_totp_secret!: string | null;"
			: mfa === "sms"
				? "\n\tsms_mfa_enabled?: boolean;\n\tmobile_number?: string;"
				: "";

	const recoveryCodesImport =
		mfa === "totp" ? `import RecoveryCode from "./RecoveryCode.js";\n` : "";

	const relationMappings =
		mfa === "totp"
			? `
	static get relationMappings() {
		return {
			recoveryCodes: {
				relation: Model.HasManyRelation,
				modelClass: RecoveryCode,
				join: {
					from: "users.id",
					to: "recovery_codes.user_id",
				},
			},
		};
	}
`
			: "";

	const updatePasswordMethod = forgotPassword
		? `
	async updatePassword(password: string) {
		await this.$query().patch({ password: await auth.hashPassword(password) });
	}
`
		: "";

	const authenticateReturn =
		mfa === "totp"
			? "return Object.assign(user, { isUsingMFA: !!user.mfa_totp_secret });"
			: "return user;";

	return `import { Model } from "objection";
${recoveryCodesImport}import { auth } from "../lib/auth.js";

// TODO: call Model.knex(<your knex connection>) somewhere in your app's
// setup before this model is used.
class User extends Model {
	id!: number;
	username!: string;
	email!: string;
	password!: string;${mfaField}

	static get tableName() {
		return "users";
	}
${relationMappings}
	async $beforeInsert() {
		this.password = await auth.hashPassword(this.password);
	}
${updatePasswordMethod}
	static async authenticate({
		identifier,
		password,
	}: {
		identifier: string;
		password: string;
	}) {
		const user = await User.query()
			.where("username", identifier)
			.orWhere("email", identifier)
			.first();
		if (!user) return null;

		const isValid = await auth.verifyPassword(password, user.password);
		if (!isValid) return null;

		${authenticateReturn}
	}
}

export default User;
`;
}

export function sessionModelTemplate(): string {
	return `import crypto from "node:crypto";
import { Model } from "objection";
import User from "./User.js";

class Session extends Model {
	id!: number;
	user_id!: number;
	access_token!: string;
	refresh_token!: string;
	access_token_expires_at!: string;
	refresh_token_expires_at!: string;
	user_agent?: string;
	ip_address?: string;

	static get tableName() {
		return "sessions";
	}

	static get relationMappings() {
		return {
			user: {
				relation: Model.BelongsToOneRelation,
				modelClass: User,
				join: {
					from: "sessions.user_id",
					to: "users.id",
				},
			},
		};
	}

	accessTokenHasExpired(): boolean {
		return new Date(this.access_token_expires_at).getTime() < Date.now();
	}

	refreshTokenHasExpired(): boolean {
		return new Date(this.refresh_token_expires_at).getTime() < Date.now();
	}

	static generateTokens() {
		const generateToken = () => crypto.randomBytes(32).toString("hex");
		const now = Date.now();
		return {
			access_token: generateToken(),
			access_token_expires_at: new Date(now + 3_600_000).toISOString(),
			refresh_token: generateToken(),
			refresh_token_expires_at: new Date(now + 86_400_000).toISOString(),
		};
	}
}

export default Session;
`;
}

export function magicLinkModelTemplate(): string {
	return `import crypto from "node:crypto";
import { Model } from "objection";
import { auth } from "../lib/auth.js";

class MagicLink extends Model {
	id!: number;
	user_id!: number;
	token!: string;
	hashed_code!: string;
	expires_at!: string;
	used_at?: string;

	static get tableName() {
		return "magic_links";
	}

	static async generateTokens() {
		const token = crypto.randomBytes(32).toString("hex");
		const code = crypto.randomInt(100_000, 999_999).toString();
		const hashedCode = await auth.hashPassword(code);
		const tokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
		return { token, tokenExpiresAt, code, hashedCode };
	}

	static async verifyTokenAndCode(token: string, code: string) {
		const record = await MagicLink.query().where({ token }).first();
		if (!record) throw new Error("Invalid token");
		if (record.used_at) throw new Error("Token has already been used");
		if (new Date(record.expires_at) < new Date()) {
			throw new Error("Token has expired");
		}

		const isValid = await auth.verifyPassword(code, record.hashed_code);
		if (!isValid) throw new Error("Invalid code");

		await record.$query().patch({ used_at: new Date().toISOString() });
		return { userId: record.user_id };
	}
}

export default MagicLink;
`;
}

export function smsCodeModelTemplate(): string {
	return `import { Model } from "objection";
import { auth } from "../lib/auth.js";

class SmsCode extends Model {
	id!: number;
	user_id!: number;
	token!: string;
	hashed_code!: string;
	expires_at!: string;
	used_at?: string;

	static get tableName() {
		return "sms_codes";
	}

	codeHasExpired(): boolean {
		return new Date(this.expires_at).getTime() < Date.now();
	}

	async verifyCode(code: string): Promise<boolean> {
		return auth.verifyPassword(code, this.hashed_code);
	}
}

export default SmsCode;
`;
}

export function mfaTokenModelTemplate(): string {
	return `import { Model } from "objection";

class MfaToken extends Model {
	id!: number;
	user_id!: number;
	token!: string;
	expires_at!: string;
	used_at?: string;
	number_of_attempts!: number;

	static get tableName() {
		return "mfa_tokens";
	}
}

export default MfaToken;
`;
}

export function recoveryCodeModelTemplate(): string {
	return `import crypto from "node:crypto";
import { Model } from "objection";
import { auth } from "../lib/auth.js";

const NUMBER_OF_RECOVERY_CODES = 10;

class RecoveryCode extends Model {
	id!: number;
	user_id!: number;
	// Plaintext code, only used transiently when generating - never persisted
	// (see $beforeInsert below, which hashes it into hashed_code instead).
	code?: string;
	hashed_code!: string;
	used_at?: string;

	static get tableName() {
		return "recovery_codes";
	}

	async $beforeInsert() {
		if (this.code) {
			this.hashed_code = await auth.hashPassword(this.code);
		}
	}

	static generateCodes(): Promise<string[]> {
		const codes = Array.from({ length: NUMBER_OF_RECOVERY_CODES }, () =>
			crypto.randomBytes(5).toString("hex").toUpperCase(),
		);
		return Promise.resolve(codes);
	}

	static async checkForRecoveryCodeAndConsume(
		userId: number,
		code: string,
	): Promise<boolean> {
		const unused = await RecoveryCode.query().where({
			user_id: userId,
			used_at: null,
		});
		for (const record of unused) {
			if (await auth.verifyPassword(code, record.hashed_code)) {
				await record.$query().patch({ used_at: new Date().toISOString() });
				return true;
			}
		}
		return false;
	}
}

export default RecoveryCode;
`;
}

export function forgotPasswordModelTemplate(): string {
	return `import { Model } from "objection";

class ForgotPassword extends Model {
	id!: number;
	user_id!: number;
	selector!: string;
	token_hash!: string;
	expires_at!: Date;
	used_at?: Date | null;

	static get tableName() {
		return "forgot_passwords";
	}

	async markAsUsed() {
		await this.$query().patch({ used_at: new Date() });
	}
}

export default ForgotPassword;
`;
}
