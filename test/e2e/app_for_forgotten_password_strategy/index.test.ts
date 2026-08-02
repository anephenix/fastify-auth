import { describe, it } from "vitest";

describe("app_for_forgotten_password_strategy", () => {
	describe("POST /forgot-password", () => {
		describe("when there is no identifier in the body", () => {
			it.todo("should return a 400 error");
		});

		describe("when there is an identifier in the body", () => {
			describe("when the identifier is invalid", () => {
				it.todo("should return a 400 error");
			});

			describe("when the identifier is valid", () => {
				it.todo("should return a 200 response");
				it.todo("should call the hooks.onForgotPassword hook");
			});
		});
	});

	describe("GET /reset-password/:selector", () => {
		describe("when no selector is provided", () => {
			it.todo("should return a 400 error");
		});

		describe("when no token is provided", () => {
			it.todo("should return a 400 error");
		});

		describe("when a selector and token are provided", () => {
			describe("but it does not find a record for the selector", () => {
				it.todo("should return a 400 error");
			});

			describe("and it finds a record for the selector", () => {
				describe("but the record has expired", () => {
					it.todo("should return a 400 error");
				});

				describe("but the record is already used", () => {
					it.todo("should return a 400 error");
				});

				describe("but the token is not valid", () => {
					it.todo("should return a 400 error");
				});

				describe("and the token is valid", () => {
					it.todo("should return a 200 response");
				});
			});
		});
	});

	describe("POST /reset-password", () => {
		describe("when no password is provided", () => {
			it.todo("should return a 400 error");
		});

		describe("when no password confirmation is provided", () => {
			it.todo("should return a 400 error");
		});

		describe("when a password and password confirmation are provided", () => {
			describe("but the password and password confirmation do not match", () => {
				it.todo("should return a 400 error");
			});

			describe("and the password and password confirmation match", () => {
				describe("but the password does not meet validation criteria", () => {
					it.todo("should return a 400 error");
				});

				describe("and the password meets validation criteria", () => {
					describe("when no selector is provided", () => {
						it.todo("should return a 400 error");
					});

					describe("when no token is provided", () => {
						it.todo("should return a 400 error");
					});

					describe("when a selector and token are provided", () => {
						describe("but a record is not found for the selector", () => {
							it.todo("should return a 400 error");
						});

						describe("and a record is found for the selector", () => {
							describe("but the record has expired", () => {
								it.todo("should return a 400 error");
							});

							describe("but the record is already used", () => {
								it.todo("should return a 400 error");
							});

							describe("but the token is not valid", () => {
								it.todo("should return a 400 error");
							});

							describe("and the token is valid", () => {
								describe("but it does not find a user for the record", () => {
									it.todo("should return a 400 error");
								});

								describe("and it finds a user for the record", () => {
									it.todo("should update the user's password");
									it.todo("should mark the record as used");
									it.todo("should return a 200 response");
									// NOTE - should we call a hook for when the password is updated, like for sending an email? Or could that be handled by the Objection.js model?
								});
							});
						});
					});
				});
			});
		});
	});
});
