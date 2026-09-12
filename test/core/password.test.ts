import type { Auth } from "@anephenix/auth";
import { describe, expect, it, vi } from "vitest";
import { RateLimitedError, verifyPassword } from "../../src/core/password.js";
import type { IUserModelStatic } from "../../src/types.js";

function buildAuth(overrides: Record<string, unknown> = {}) {
	return {
		loginWindowSeconds: 900,
		verifyPasswordSafe: vi.fn().mockResolvedValue(true),
		checkRateLimit: vi
			.fn()
			.mockReturnValue({ blocked: false, remainingAttempts: 5 }),
		...overrides,
	} as unknown as Auth;
}

function buildUser(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		username: "alice",
		hashed_password: "hashed_secret",
		failed_login_attempts: 0,
		failed_login_window_started_at: null,
		$query: vi.fn().mockReturnValue({ patch: vi.fn().mockResolvedValue(1) }),
		...overrides,
	};
}

describe("verifyPassword", () => {
	it("throws when identifier is missing", async () => {
		const User = { findByIdentifier: vi.fn() } as unknown as IUserModelStatic;
		await expect(
			verifyPassword(buildAuth(), User, "", "secret"),
		).rejects.toThrow("Please provide your username or email address");
		expect(User.findByIdentifier).not.toHaveBeenCalled();
	});

	it("throws when password is missing", async () => {
		const User = { findByIdentifier: vi.fn() } as unknown as IUserModelStatic;
		await expect(
			verifyPassword(buildAuth(), User, "alice", ""),
		).rejects.toThrow("Password is required");
		expect(User.findByIdentifier).not.toHaveBeenCalled();
	});

	it("looks the user up and returns it (with isUsingMFA) on a correct password", async () => {
		const user = buildUser({ mfa_totp_secret: "secret" });
		const findByIdentifier = vi.fn().mockResolvedValue(user);
		const User = { findByIdentifier } as unknown as IUserModelStatic;
		const auth = buildAuth();

		const result = await verifyPassword(auth, User, "alice", "secret");

		expect(findByIdentifier).toHaveBeenCalledWith("alice");
		expect(auth.verifyPasswordSafe).toHaveBeenCalledWith(
			"secret",
			"hashed_secret",
		);
		expect(result).toMatchObject({ id: 1, username: "alice" });
		expect(result?.isUsingMFA).toBe(true);
	});

	it("returns null when the password is wrong, without leaking that via a distinct error", async () => {
		const user = buildUser();
		const User = {
			findByIdentifier: vi.fn().mockResolvedValue(user),
		} as unknown as IUserModelStatic;
		const auth = buildAuth({
			verifyPasswordSafe: vi.fn().mockResolvedValue(false),
		});

		const result = await verifyPassword(auth, User, "alice", "wrong");
		expect(result).toBeNull();
	});

	it("returns null when the identifier doesn't match any user, but still runs the timing-safe check", async () => {
		const User = {
			findByIdentifier: vi.fn().mockResolvedValue(undefined),
		} as unknown as IUserModelStatic;
		const auth = buildAuth({
			verifyPasswordSafe: vi.fn().mockResolvedValue(false),
		});

		const result = await verifyPassword(auth, User, "nonexistent", "secret");

		expect(result).toBeNull();
		// verifyPasswordSafe is always called - with an undefined hash when no
		// user was found - so that response timing can't be used to enumerate
		// valid identifiers.
		expect(auth.verifyPasswordSafe).toHaveBeenCalledWith("secret", undefined);
	});

	it("increments failed_login_attempts and starts a window on a wrong password", async () => {
		const patch = vi.fn().mockResolvedValue(1);
		const user = buildUser({
			failed_login_attempts: 0,
			failed_login_window_started_at: null,
			$query: vi.fn().mockReturnValue({ patch }),
		});
		const User = {
			findByIdentifier: vi.fn().mockResolvedValue(user),
		} as unknown as IUserModelStatic;
		const auth = buildAuth({
			verifyPasswordSafe: vi.fn().mockResolvedValue(false),
		});

		await verifyPassword(auth, User, "alice", "wrong");

		expect(patch).toHaveBeenCalledWith(
			expect.objectContaining({ failed_login_attempts: 1 }),
		);
	});

	it("resets failed_login_attempts on a successful login", async () => {
		const patch = vi.fn().mockResolvedValue(1);
		const user = buildUser({
			failed_login_attempts: 2,
			failed_login_window_started_at: new Date().toISOString(),
			$query: vi.fn().mockReturnValue({ patch }),
		});
		const User = {
			findByIdentifier: vi.fn().mockResolvedValue(user),
		} as unknown as IUserModelStatic;
		const auth = buildAuth();

		await verifyPassword(auth, User, "alice", "secret");

		expect(patch).toHaveBeenCalledWith({
			failed_login_attempts: 0,
			failed_login_window_started_at: null,
		});
	});

	it("throws RateLimitedError without calling verifyPasswordSafe when the account is currently blocked", async () => {
		const user = buildUser({
			failed_login_attempts: 5,
			failed_login_window_started_at: new Date().toISOString(),
		});
		const User = {
			findByIdentifier: vi.fn().mockResolvedValue(user),
		} as unknown as IUserModelStatic;
		const auth = buildAuth({
			checkRateLimit: vi.fn().mockReturnValue({
				blocked: true,
				remainingAttempts: 0,
				retryAfter: 42,
			}),
		});

		const error = await verifyPassword(auth, User, "alice", "secret").catch(
			(e) => e,
		);
		expect(error).toBeInstanceOf(RateLimitedError);
		expect((error as RateLimitedError).retryAfter).toBe(42);
		expect(auth.verifyPasswordSafe).not.toHaveBeenCalled();
	});

	it("does not rate limit once the window has expired, even with a high attempt count", async () => {
		const user = buildUser({
			failed_login_attempts: 10,
			failed_login_window_started_at: new Date(
				Date.now() - 2000 * 1000,
			).toISOString(),
		});
		const User = {
			findByIdentifier: vi.fn().mockResolvedValue(user),
		} as unknown as IUserModelStatic;
		const auth = buildAuth();

		const result = await verifyPassword(auth, User, "alice", "secret");
		expect(result).toMatchObject({ id: 1 });
		expect(auth.checkRateLimit).not.toHaveBeenCalled();
	});
});
