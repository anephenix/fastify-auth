import crypto from "node:crypto";
import { db, type FakeMagicLink } from "../fakeDb.js";
import { auth } from "../lib/auth.js";

const MagicLink = {
	query() {
		return {
			async insert(data: {
				user_id: number;
				token: string;
				hashed_code: string;
				expires_at: string;
			}) {
				const record: FakeMagicLink = {
					id: db.nextId.magicLink++,
					used_at: null,
					...data,
				};
				db.magicLinks.push(record);
				return record;
			},
		};
	},
	async generateTokens() {
		const token = crypto.randomBytes(16).toString("hex");
		const code = "123456";
		const hashedCode = await auth.hashPassword(code);
		const tokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
		return { token, tokenExpiresAt, code, hashedCode };
	},
	async verifyTokenAndCode(token: string, code: string) {
		const record = db.magicLinks.find((m) => m.token === token);
		if (!record) throw new Error("Invalid token");
		if (record.used_at) throw new Error("Token has already been used");
		if (new Date(record.expires_at) < new Date()) {
			throw new Error("Token has expired");
		}

		const isValid = await auth.verifyPassword(code, record.hashed_code);
		if (!isValid) throw new Error("Invalid code");

		record.used_at = new Date().toISOString();
		return { userId: record.user_id };
	},
};

export default MagicLink;
