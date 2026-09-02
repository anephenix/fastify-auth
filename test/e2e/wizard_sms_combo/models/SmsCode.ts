import { db, type FakeSmsCode, matches } from "../fakeDb.js";
import { auth } from "../lib/auth.js";

function wrapSmsCode(record: FakeSmsCode) {
	return {
		...record,
		codeHasExpired: () => new Date(record.expires_at).getTime() < Date.now(),
		verifyCode: (code: string) => auth.verifyPassword(code, record.hashed_code),
		$query() {
			return {
				patch: async (data: Partial<FakeSmsCode>) => {
					Object.assign(record, data);
				},
			};
		},
	};
}

const SmsCode = {
	query() {
		return {
			async insert(data: {
				user_id: number;
				token: string;
				hashed_code: string;
				expires_at: string;
			}) {
				const record: FakeSmsCode = {
					id: db.nextId.smsCode++,
					used_at: null,
					...data,
				};
				db.smsCodes.push(record);
				return wrapSmsCode(record);
			},
			findOne: async (criteria: Record<string, unknown>) => {
				const record = db.smsCodes.find((s) => matches(s, criteria));
				return record ? wrapSmsCode(record) : undefined;
			},
		};
	},
};

export default SmsCode;
