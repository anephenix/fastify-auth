import type { Auth } from "@anephenix/auth";
import { describe, expect, it, vi } from "vitest";
import { validateResetToken } from "../../src/core/forgot-password.js";
import type { IForgotPasswordModelStatic } from "../../src/types.js";

function buildForgotPassword(record: unknown) {
	return {
		query: vi.fn().mockReturnValue({
			where: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(record),
			}),
		}),
	} as unknown as IForgotPasswordModelStatic;
}

const validRecord = {
	id: 1,
	user_id: 42,
	selector: "sel-1",
	token_hash: "hashed-token",
	expires_at: new Date(Date.now() + 3_600_000),
	used_at: null,
};

describe("validateResetToken", () => {
	it("reports invalid when no record matches the selector", async () => {
		const ForgotPassword = buildForgotPassword(undefined);
		const auth = { verifyPassword: vi.fn() } as unknown as Auth;

		const result = await validateResetToken({
			ForgotPassword,
			auth,
			selector: "unknown",
			token: "tok",
		});

		expect(result).toEqual({
			valid: false,
			error: "Invalid reset password selector or token",
		});
	});

	it("reports expired when the record's expiry has passed", async () => {
		const ForgotPassword = buildForgotPassword({
			...validRecord,
			expires_at: new Date(Date.now() - 1000),
		});
		const auth = { verifyPassword: vi.fn() } as unknown as Auth;

		const result = await validateResetToken({
			ForgotPassword,
			auth,
			selector: "sel-1",
			token: "tok",
		});

		expect(result).toEqual({
			valid: false,
			error: "Password reset token has expired",
		});
	});

	it("reports already-used when the record has a used_at timestamp", async () => {
		const ForgotPassword = buildForgotPassword({
			...validRecord,
			used_at: new Date().toISOString(),
		});
		const auth = { verifyPassword: vi.fn() } as unknown as Auth;

		const result = await validateResetToken({
			ForgotPassword,
			auth,
			selector: "sel-1",
			token: "tok",
		});

		expect(result).toEqual({
			valid: false,
			error: "Password reset token has already been used",
		});
	});

	it("reports invalid when the token doesn't match the stored hash", async () => {
		const ForgotPassword = buildForgotPassword(validRecord);
		const auth = {
			verifyPassword: vi.fn().mockResolvedValue(false),
		} as unknown as Auth;

		const result = await validateResetToken({
			ForgotPassword,
			auth,
			selector: "sel-1",
			token: "wrong-token",
		});

		expect(auth.verifyPassword).toHaveBeenCalledWith(
			"wrong-token",
			"hashed-token",
		);
		expect(result).toEqual({
			valid: false,
			error: "Invalid reset password selector or token",
		});
	});

	it("returns the record when everything checks out", async () => {
		const ForgotPassword = buildForgotPassword(validRecord);
		const auth = {
			verifyPassword: vi.fn().mockResolvedValue(true),
		} as unknown as Auth;

		const result = await validateResetToken({
			ForgotPassword,
			auth,
			selector: "sel-1",
			token: "correct-token",
		});

		expect(result).toEqual({ valid: true, record: validRecord });
	});
});
