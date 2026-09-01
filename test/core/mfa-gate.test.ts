import type { Auth } from "@anephenix/auth";
import { describe, expect, it, vi } from "vitest";
import { issueMfaChallenge } from "../../src/core/mfa-gate.js";
import type { IMfaTokenModelStatic } from "../../src/types.js";

describe("issueMfaChallenge", () => {
	it("generates an mfa token, persists it, and returns the lookup token", async () => {
		const expiresAt = new Date(Date.now() + 30_000);
		const auth = {
			generateMfaLoginToken: vi
				.fn()
				.mockResolvedValue({ token: "mfa_token_abc", expiresAt }),
		} as unknown as Auth;

		const insert = vi.fn().mockResolvedValue({ id: 1 });
		const MfaToken = {
			query: vi.fn().mockReturnValue({ insert }),
		} as unknown as IMfaTokenModelStatic;

		const result = await issueMfaChallenge(MfaToken, auth, 42);

		expect(insert).toHaveBeenCalledWith({
			user_id: 42,
			token: "mfa_token_abc",
			expires_at: expiresAt.toISOString(),
			number_of_attempts: 0,
		});
		expect(result).toEqual({ token: "mfa_token_abc" });
	});
});
