import { db, type FakeForgotPassword } from "../fakeDb.js";

function wrapForgotPassword(record: FakeForgotPassword) {
	return {
		...record,
		async markAsUsed() {
			record.used_at = new Date();
		},
	};
}

const ForgotPassword = {
	query() {
		return {
			async insert(data: {
				user_id: number;
				selector: string;
				token_hash: string;
				expires_at: Date;
			}) {
				const record: FakeForgotPassword = {
					id: db.nextId.forgotPassword++,
					used_at: null,
					...data,
				};
				db.forgotPasswords.push(record);
				return wrapForgotPassword(record);
			},
			where(column: string, value: unknown) {
				return {
					first: async () => {
						const record = db.forgotPasswords.find(
							(r) =>
								(r as unknown as Record<string, unknown>)[column] === value,
						);
						return record ? wrapForgotPassword(record) : undefined;
					},
				};
			},
		};
	},
};

export default ForgotPassword;
