import { describe, it } from "vitest";

describe("app_for_sessions_strategy", () => {
	describe("POST /signup", () => {
		describe("when an invalid user payload is provided", () => {
			it.todo("should not create a user record in the database");
			it.todo("should return a 400 HTTP status and a message of the error");
		});

		describe("when a valid user payload is provided", () => {
			it.todo("should create a user record in the database");
			it.todo("should return a 201 HTTP status and the created user details");
		});
	});
	describe("POST /login", () => {
		describe("when no identifier is provided", () => {
			it.todo(
				"should return a 400 HTTP status and a message asking to provide a username or email address",
			);
		});

		describe("when no password is provided", () => {
			it.todo(
				"should return a 400 HTTP status and a message asking to provide a password",
			);
		});

		describe("when the user authentication is invalid", () => {
			it.todo(
				"should return a 401 HTTP status and a message asking to provide valid credentials",
			);
		});

		describe("when the user authentication is valid", () => {
			it.todo("should create a session record in the database for the user");

			describe("and when the clientType is web", () => {
				it.todo("should set a cookie for the access_token");
				it.todo("should set a cookie for the refresh_token");
				it.todo(
					"should return a 200 HTTP status saying Authenticated successfully",
				);
			});

			describe("and when the clientType is api", () => {
				it.todo(
					"should return a 200 HTTP status and the access and refresh tokens",
				);
			});
		});
	});

	describe("GET /profile", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			it.todo("should return the user details");
		});
	});

	describe("POST /logout", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			it.todo("should delete the session record in the database for the user");
			it.todo("should clear any cookies related to the session");
			it.todo(
				"should response with a 200 and a message saying Logged out successfully",
			);
		});
	});

	describe("POST /auth/refresh", () => {
		describe("when there is no refresh_token provided", () => {
			it.todo(
				"should respond with a HTTP status 401 and a message saying No refresh token provided",
			);
		});

		describe("when the refresh token has expired", () => {
			it.todo(
				"should respond with a HTTP status 401 and a message saying Invalid or expired refresh token",
			);
		});

		describe("when the refresh token is valid", () => {
			it.todo("should update the session with a new access token");

			describe("when the client type is web", () => {
				it.todo("should set the access token cookie with the latest values");
				it.todo(
					"should respond with a 201 HTTP status and a message saying that the token was refreshed successfully",
				);
			});

			describe("when the client type is api", () => {
				it.todo(
					"should respond with a 201 HTTP status and the update access_token and refresh_token values",
				);
			});
		});
	});

	describe("GET /sessions", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			it.todo("should return the list of sessions for the logged-in user");
		});
	});
	describe("DELETE /sessions", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is a logged-in user", () => {
			it.todo(
				"should delete all sessions for the logged-in user, except the current session that the user is using",
			);
		});
	});
	describe("DELETE /sessions/:id", () => {
		describe("when there is no logged-in user", () => {
			it.todo("should respond with a HTTP status 401 and unauthorized payload");
		});

		describe("when there is no session found for the session id provided", () => {
			it.todo("should respond with a HTTP status 404 and not found payload");
		});

		describe("when the found session access is the same as the current session", () => {
			it.todo(
				"should respond with a HTTP status 400 and inform the user to use the logout endpoint to end the session",
			);
		});

		describe("when the found session access is different from the current session", () => {
			it.todo("should respond with a HTTP status 200 and delete the session");
		});
	});
});
