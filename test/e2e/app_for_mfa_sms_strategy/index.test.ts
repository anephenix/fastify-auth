import { describe, it } from "vitest";

describe("app_for_mfa_sms_strategy", () => {
	describe("/POST sessions", () => {
		describe("when a user fails to authenticate", () => {
			describe("because no identifier is provided", () => {
				it.todo("should return a 400 error");
			});

			describe("because the identifier is invalid", () => {
				it.todo("should return a 401 error");
			});

			describe("because no password is provided", () => {
				it.todo("should return a 401 error");
			});

			describe("because the password is incorrect", () => {
				it.todo("should return a 401 error");
			});
		});

		describe("when a user authenticates successfully", () => {
			it.todo("should return a 200 response");
			it.todo("should generate an sms code record");
			it.todo("should send the sms code to the user via a hook");
		});
	});

	describe("/sessions/verify-code", () => {
		describe("when there is no token", () => {
			it.todo("should return a 400 error");
		});

		describe("when there is no code", () => {
			it.todo("should return a 400 error");
		});

		describe("when no sms code is found for the token", () => {
			it.todo("should return a 400 error");
		});

		describe("when the sms code is found, but has already been used", () => {
			it.todo("should return a 400 error");
		});

		describe("when the sms code is found but has expired", () => {
			it.todo("should return a 400 error");
		});

		describe("when the sms code is found, but the code is invalid", () => {
			it.todo("should return a 400 error");
		});

		describe("when the sms code is found and the code is valid", () => {
			it.todo(
				"should update the sms code record with the used_at date field set to the current date and time",
			);
			it.todo(
				"should create a session record for the user from the sms code record, with tokens",
			);
			it.todo("should return a 201 response and return the session tokens");
		});
	});
});
