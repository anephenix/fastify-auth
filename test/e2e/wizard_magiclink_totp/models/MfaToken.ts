import { db, type FakeMfaToken, matches } from "../fakeDb.js";

function wrapMfaToken(record: FakeMfaToken) {
	return {
		...record,
		$query() {
			return {
				increment: async (field: "number_of_attempts", by: number) => {
					record[field] += by;
				},
				patch: async (data: Partial<FakeMfaToken>) => {
					Object.assign(record, data);
				},
			};
		},
	};
}

const MfaToken = {
	query() {
		return {
			async insert(data: {
				user_id: number;
				token: string;
				expires_at: string;
				number_of_attempts: number;
			}) {
				const record: FakeMfaToken = {
					id: db.nextId.mfaToken++,
					used_at: null,
					...data,
				};
				db.mfaTokens.push(record);
				return wrapMfaToken(record);
			},
			where(criteria: Record<string, unknown>) {
				return {
					first: async () => {
						const record = db.mfaTokens.find((m) => matches(m, criteria));
						return record ? wrapMfaToken(record) : undefined;
					},
				};
			},
		};
	},
};

export default MfaToken;
