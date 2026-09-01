import { describe, expect, it, vi } from "vitest";
import { verifyPassword } from "../../src/core/password.js";
import type { IUserModelStatic } from "../../src/types.js";

describe("verifyPassword", () => {
	it("throws when identifier is missing", async () => {
		const User = { authenticate: vi.fn() } as unknown as IUserModelStatic;
		await expect(verifyPassword(User, "", "secret")).rejects.toThrow(
			"Please provide your username or email address",
		);
		expect(User.authenticate).not.toHaveBeenCalled();
	});

	it("throws when password is missing", async () => {
		const User = { authenticate: vi.fn() } as unknown as IUserModelStatic;
		await expect(verifyPassword(User, "alice", "")).rejects.toThrow(
			"Password is required",
		);
		expect(User.authenticate).not.toHaveBeenCalled();
	});

	it("delegates to User.authenticate and returns its result", async () => {
		const mockUser = { id: 1, username: "alice" };
		const authenticate = vi.fn().mockResolvedValue(mockUser);
		const User = { authenticate } as unknown as IUserModelStatic;

		const result = await verifyPassword(User, "alice", "secret");

		expect(authenticate).toHaveBeenCalledWith({
			identifier: "alice",
			password: "secret",
		});
		expect(result).toBe(mockUser);
	});

	it("returns null when authenticate reports invalid credentials", async () => {
		const authenticate = vi.fn().mockResolvedValue(null);
		const User = { authenticate } as unknown as IUserModelStatic;

		const result = await verifyPassword(User, "alice", "wrong");
		expect(result).toBeNull();
	});
});
