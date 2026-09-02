import crypto from "node:crypto";
import { db, type FakeRecoveryCode } from "../fakeDb.js";
import { auth } from "../lib/auth.js";

const NUMBER_OF_RECOVERY_CODES = 10;

const RecoveryCode = {
	query() {
		return {
			async insert(data: { user_id: number; code: string }) {
				const record: FakeRecoveryCode = {
					id: db.nextId.recoveryCode++,
					user_id: data.user_id,
					hashed_code: await auth.hashPassword(data.code),
					used_at: null,
				};
				db.recoveryCodes.push(record);
				return record;
			},
		};
	},
	generateCodes(): Promise<string[]> {
		return Promise.resolve(
			Array.from({ length: NUMBER_OF_RECOVERY_CODES }, () =>
				crypto.randomBytes(5).toString("hex").toUpperCase(),
			),
		);
	},
	async checkForRecoveryCodeAndConsume(
		userId: number,
		code: string,
	): Promise<boolean> {
		const unused = db.recoveryCodes.filter(
			(r) => r.user_id === userId && r.used_at === null,
		);
		for (const record of unused) {
			if (await auth.verifyPassword(code, record.hashed_code)) {
				record.used_at = new Date().toISOString();
				return true;
			}
		}
		return false;
	},
};

export default RecoveryCode;
