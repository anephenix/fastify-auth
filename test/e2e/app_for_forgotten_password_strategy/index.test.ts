import { beforeEach, describe, expect, it } from "vitest";
import { type BuiltApp, buildApp } from "./index.js";

// ─── Test helpers ─────────────────────────────────────────────────────────────

const ALICE = {
	username: "alice",
	email: "alice@example.com",
	password: "correct-horse-battery-staple",
};

function seedAlice(ctx: BuiltApp) {
	return ctx.addUser(ALICE);
}

async function requestForgotPassword(ctx: BuiltApp, identifier: string) {
	return ctx.app.inject({
		method: "POST",
		url: "/forgot-password",
		payload: { identifier },
	});
}

/** Seeds a user and drives a real forgot-password request to get a live selector/token pair. */
async function triggerResetForAlice(ctx: BuiltApp) {
	const user = seedAlice(ctx);
	await requestForgotPassword(ctx, ALICE.email);
	const sent = ctx.sentResets.at(-1);
	if (!sent?.selector || !sent.token) {
		throw new Error(
			"Expected onForgotPasswordRequested to have run for a known user",
		);
	}
	return { user, selector: sent.selector, token: sent.token };
}

describe("app_for_forgotten_password_strategy", () => {
	let ctx: BuiltApp;

	beforeEach(async () => {
		ctx = buildApp();
		await ctx.app.ready();
	});

	describe("POST /forgot-password", () => {
		describe("when there is no identifier in the body", () => {
			it("should return a 400 error", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/forgot-password",
					payload: {},
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toHaveProperty("error");
			});
		});

		describe("when there is an identifier in the body", () => {
			describe("when the identifier is invalid", () => {
				it("should return a 400 error", async () => {
					const response = await requestForgotPassword(
						ctx,
						"not a valid identifier!",
					);
					expect(response.statusCode).toBe(400);
					expect(response.json()).toMatchObject({
						error: "Invalid identifier",
					});
				});
			});

			describe("when the identifier is valid", () => {
				it("should return a 200 response", async () => {
					seedAlice(ctx);
					const response = await requestForgotPassword(ctx, ALICE.email);
					expect(response.statusCode).toBe(200);
					expect(response.json().message).toMatch(
						/password reset instructions/i,
					);
				});

				it("should call the hooks.onForgotPassword hook", async () => {
					seedAlice(ctx);
					await requestForgotPassword(ctx, ALICE.email);
					expect(ctx.sentResets).toHaveLength(1);
					expect(ctx.sentResets[0]).toMatchObject({
						identifier: ALICE.email,
						isEmail: true,
					});
				});

				it("returns the same neutral 200 response even when no account matches, to prevent user enumeration", async () => {
					const response = await requestForgotPassword(
						ctx,
						"nobody@example.com",
					);
					expect(response.statusCode).toBe(200);
					expect(response.json().message).toMatch(
						/password reset instructions/i,
					);
					// The hook still fires (so a real app's lookup runs), it just finds no user.
					expect(ctx.sentResets).toHaveLength(1);
					expect(ctx.sentResets[0].selector).toBeUndefined();
				});
			});
		});
	});

	describe("GET /reset-password/:selector", () => {
		describe("when no selector is provided", () => {
			it("should return a 400 error", async () => {
				// A trailing-slash request matches `:selector` as an empty string
				// rather than 404ing, so the strategy's own `!selector` guard fires.
				const response = await ctx.app.inject({
					method: "GET",
					url: "/reset-password/",
					query: { token: "some-token" },
				});
				expect(response.statusCode).toBe(400);
				expect(response.json().error).toMatch(/invalid/i);
			});
		});

		describe("when no token is provided", () => {
			it("should return a 400 error", async () => {
				const { selector } = await triggerResetForAlice(ctx);
				const response = await ctx.app.inject({
					method: "GET",
					url: `/reset-password/${selector}`,
				});
				expect(response.statusCode).toBe(400);
				expect(response.json().error).toMatch(/invalid/i);
			});
		});

		describe("when a selector and token are provided", () => {
			describe("but it does not find a record for the selector", () => {
				it("should return a 400 error", async () => {
					const response = await ctx.app.inject({
						method: "GET",
						url: "/reset-password/unknown-selector?token=some-token",
					});
					expect(response.statusCode).toBe(400);
					expect(response.json().error).toMatch(/invalid/i);
				});
			});

			describe("and it finds a record for the selector", () => {
				describe("but the record has expired", () => {
					it("should return a 400 error", async () => {
						const { selector, token } = await triggerResetForAlice(ctx);
						ctx.forgotPasswordRecords[0].expires_at = new Date(
							Date.now() - 1000,
						);
						const response = await ctx.app.inject({
							method: "GET",
							url: `/reset-password/${selector}?token=${token}`,
						});
						expect(response.statusCode).toBe(400);
						expect(response.json().error).toMatch(/expired/i);
					});
				});

				describe("but the record is already used", () => {
					it("should return a 400 error", async () => {
						const { selector, token } = await triggerResetForAlice(ctx);
						await ctx.forgotPasswordRecords[0].markAsUsed();
						const response = await ctx.app.inject({
							method: "GET",
							url: `/reset-password/${selector}?token=${token}`,
						});
						expect(response.statusCode).toBe(400);
						expect(response.json().error).toMatch(/already been used/i);
					});
				});

				describe("but the token is not valid", () => {
					it("should return a 400 error", async () => {
						const { selector } = await triggerResetForAlice(ctx);
						const response = await ctx.app.inject({
							method: "GET",
							url: `/reset-password/${selector}?token=wrong-token`,
						});
						expect(response.statusCode).toBe(400);
						expect(response.json().error).toMatch(/invalid/i);
					});
				});

				describe("and the token is valid", () => {
					it("should return a 200 response", async () => {
						const { selector, token } = await triggerResetForAlice(ctx);
						const response = await ctx.app.inject({
							method: "GET",
							url: `/reset-password/${selector}?token=${token}`,
						});
						expect(response.statusCode).toBe(200);
						expect(response.json()).toMatchObject({
							message: "Password reset token is valid",
						});
					});
				});
			});
		});
	});

	describe("POST /reset-password", () => {
		describe("when no password is provided", () => {
			it("should return a 400 error", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/reset-password",
					payload: {
						selector: "some-selector",
						token: "some-token",
						password_confirmation: "new-password-123",
					},
				});
				expect(response.statusCode).toBe(400);
				expect(response.json().error).toMatch(/required/i);
			});
		});

		describe("when no password confirmation is provided", () => {
			it("should return a 400 error", async () => {
				const response = await ctx.app.inject({
					method: "POST",
					url: "/reset-password",
					payload: {
						selector: "some-selector",
						token: "some-token",
						password: "new-password-123",
					},
				});
				expect(response.statusCode).toBe(400);
				expect(response.json().error).toMatch(/required/i);
			});
		});

		describe("when a password and password confirmation are provided", () => {
			describe("but the password and password confirmation do not match", () => {
				it("should return a 400 error", async () => {
					const response = await ctx.app.inject({
						method: "POST",
						url: "/reset-password",
						payload: {
							selector: "some-selector",
							token: "some-token",
							password: "new-password-123",
							password_confirmation: "different-password-456",
						},
					});
					expect(response.statusCode).toBe(400);
					expect(response.json().error).toMatch(/do not match/i);
				});
			});

			describe("and the password and password confirmation match", () => {
				describe("but the password does not meet validation criteria", () => {
					it("should return a 400 error", async () => {
						// Auth is configured with passwordValidationRules.minLength = 8
						const response = await ctx.app.inject({
							method: "POST",
							url: "/reset-password",
							payload: {
								selector: "some-selector",
								token: "some-token",
								password: "short",
								password_confirmation: "short",
							},
						});
						expect(response.statusCode).toBe(400);
						expect(response.json().error).toMatch(/validation/i);
					});
				});

				describe("and the password meets validation criteria", () => {
					describe("when no selector is provided", () => {
						it("should return a 400 error", async () => {
							const response = await ctx.app.inject({
								method: "POST",
								url: "/reset-password",
								payload: {
									token: "some-token",
									password: "new-password-123",
									password_confirmation: "new-password-123",
								},
							});
							expect(response.statusCode).toBe(400);
							expect(response.json().error).toMatch(/invalid/i);
						});
					});

					describe("when no token is provided", () => {
						it("should return a 400 error", async () => {
							const response = await ctx.app.inject({
								method: "POST",
								url: "/reset-password",
								payload: {
									selector: "some-selector",
									password: "new-password-123",
									password_confirmation: "new-password-123",
								},
							});
							expect(response.statusCode).toBe(400);
							expect(response.json().error).toMatch(/invalid/i);
						});
					});

					describe("when a selector and token are provided", () => {
						describe("but a record is not found for the selector", () => {
							it("should return a 400 error", async () => {
								const response = await ctx.app.inject({
									method: "POST",
									url: "/reset-password",
									payload: {
										selector: "unknown-selector",
										token: "some-token",
										password: "new-password-123",
										password_confirmation: "new-password-123",
									},
								});
								expect(response.statusCode).toBe(400);
								expect(response.json().error).toMatch(/invalid/i);
							});
						});

						describe("and a record is found for the selector", () => {
							describe("but the record has expired", () => {
								it("should return a 400 error", async () => {
									const { selector, token } = await triggerResetForAlice(ctx);
									ctx.forgotPasswordRecords[0].expires_at = new Date(
										Date.now() - 1000,
									);
									const response = await ctx.app.inject({
										method: "POST",
										url: "/reset-password",
										payload: {
											selector,
											token,
											password: "new-password-123",
											password_confirmation: "new-password-123",
										},
									});
									expect(response.statusCode).toBe(400);
									expect(response.json().error).toMatch(/expired/i);
								});
							});

							describe("but the record is already used", () => {
								it("should return a 400 error", async () => {
									const { selector, token } = await triggerResetForAlice(ctx);
									await ctx.forgotPasswordRecords[0].markAsUsed();
									const response = await ctx.app.inject({
										method: "POST",
										url: "/reset-password",
										payload: {
											selector,
											token,
											password: "new-password-123",
											password_confirmation: "new-password-123",
										},
									});
									expect(response.statusCode).toBe(400);
									expect(response.json().error).toMatch(/already been used/i);
								});
							});

							describe("but the token is not valid", () => {
								it("should return a 400 error", async () => {
									const { selector } = await triggerResetForAlice(ctx);
									const response = await ctx.app.inject({
										method: "POST",
										url: "/reset-password",
										payload: {
											selector,
											token: "wrong-token",
											password: "new-password-123",
											password_confirmation: "new-password-123",
										},
									});
									expect(response.statusCode).toBe(400);
									expect(response.json().error).toMatch(/invalid/i);
								});
							});

							describe("and the token is valid", () => {
								describe("but it does not find a user for the record", () => {
									it("should return a 400 error", async () => {
										const { selector, token } = await triggerResetForAlice(ctx);
										// Simulate the referenced user having been deleted since the
										// reset record was created.
										ctx.users.length = 0;
										const response = await ctx.app.inject({
											method: "POST",
											url: "/reset-password",
											payload: {
												selector,
												token,
												password: "new-password-123",
												password_confirmation: "new-password-123",
											},
										});
										expect(response.statusCode).toBe(400);
										expect(response.json().error).toMatch(/user not found/i);
									});
								});

								describe("and it finds a user for the record", () => {
									it("should update the user's password", async () => {
										const { user, selector, token } =
											await triggerResetForAlice(ctx);
										await ctx.app.inject({
											method: "POST",
											url: "/reset-password",
											payload: {
												selector,
												token,
												password: "new-password-123",
												password_confirmation: "new-password-123",
											},
										});
										expect(user.password).toBe("new-password-123");
									});

									it("should mark the record as used", async () => {
										const { selector, token } = await triggerResetForAlice(ctx);
										await ctx.app.inject({
											method: "POST",
											url: "/reset-password",
											payload: {
												selector,
												token,
												password: "new-password-123",
												password_confirmation: "new-password-123",
											},
										});
										expect(ctx.forgotPasswordRecords[0].used_at).not.toBeNull();
									});

									it("should return a 200 response", async () => {
										const { selector, token } = await triggerResetForAlice(ctx);
										const response = await ctx.app.inject({
											method: "POST",
											url: "/reset-password",
											payload: {
												selector,
												token,
												password: "new-password-123",
												password_confirmation: "new-password-123",
											},
										});
										expect(response.statusCode).toBe(200);
										expect(response.json()).toMatchObject({
											message: "Password reset successfully",
										});
									});
								});
							});
						});
					});
				});
			});
		});
	});
});
