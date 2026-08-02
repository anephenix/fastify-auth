import { describe, it } from "vitest";

describe("app_for_mfa_totp_strategy", () => {
	describe("POST /signup", () => {
		describe("When a valid user is provided", () => {
			it.todo("should create a user record in the database");
			it.todo("should create a session record in the database");
			it.todo(
				"should return a HTTP status 201 with the access and refresh tokens",
			);
		});

		describe("When a user is invalid", () => {
			// Such as... missing username, missing email, missing password, missing mobile number
			it.todo("should a HTTP status 400, and an explanation of the error");
		});
	});

	describe("POST /login", () => {
		describe("when the login details are correct", () => {
			describe("and the user is using MFA", () => {
				it.todo("should create a MFAToken record in the database");
				it.todo(
					"should reply with a HTTP Status 201 and the MFA token in the payload",
				);
			});

			describe("but the user is not using MFA", () => {
				it.todo("should create a session record in the database");
				it.todo(
					"should return a HTTP status 201 with the access and refresh tokens",
				);
			});
		});

		describe("when the login details are not correct", () => {
			it.todo("should a HTTP status 400, and an explanation of the error");
		});
	});

	describe("POST /auth/mfa/recovery-codes", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			describe("but the recovery codes have already been generated", () => {
				it.todo(
					"should respond with a HTTP 400 Status and inform that the codes have already been generated",
				);
			});

			describe("and the recovery codes have not yet been generated", () => {
				it.todo(
					"should generate the recovery codes and return them in a HTTP 201 response",
				);
			});
		});
	});

	describe("POST /auth/mfa/setup", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			it.todo(
				"should update the user record in the database with the mfa_totp_secret",
			);
			it.todo(
				"should generate a QR Code image and return that data in the response",
			);
		});

		describe("when there is an error", () => {
			// NOTE - Why a 500 instead of a 400 - server error?
			it.todo("should respond with a HTTP status 500 and an error message");
		});
	});

	describe("POST /auth/mfa/verify", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			describe("but the token is invalid", () => {
				it.todo(
					"should respond with a HTTP 400 status and the message of Invalid TOTP token",
				);
			});

			describe("and the token is valid", () => {
				it.todo(
					"should respond with a HTTP 400 status and the message that the token is valid",
				);
			});
		});
	});
	describe("POST /auth/mfa/disable", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			describe("but the password is invalid", () => {
				it.todo(
					"should respond with a HTTP 400 status and a message that the password is invalid",
				);
			});

			describe("but the code is invalid", () => {
				it.todo(
					"should respond with a HTTP 400 status and a message that the MFA TOTP code is invalid",
				);
			});

			describe("and the password and code are valid", () => {
				it.todo(
					"should remove the mfa_totp_secret from the user record in the database",
				);
				it.todo(
					"should delete from the database all of the recovery codes that are linked to the user",
				);
				it.todo(
					"should respond with a HTTP 200 status and a message that the MFA TOTP has been disabled",
				);
			});
		});
	});

	describe("POST /auth/mfa/disable-with-recovery-code", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			describe("but the password is invalid", () => {
				it.todo(
					"should return a 400 response indicating that the password is invalid",
				);
			});

			describe("but the recovery code is invalid", () => {
				it.todo(
					"should return a 400 response indicating that the recovery code is invalid",
				);
			});

			describe("and the password and recovery code are valid", () => {
				it.todo(
					"should remove the mfa_totp_secret from the user record in the database",
				);
				it.todo(
					"should delete from the database all of the recovery codes that are linked to the user",
				);
				it.todo(
					"should respond with a HTTP 200 status and a message that the MFA TOTP has been disabled",
				);
			});
		});
	});
});
