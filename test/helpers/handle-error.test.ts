import { describe, expect, it } from "vitest";
import { handleError } from "../../src/helpers/handle-error.js";

describe("handleError", () => {
	it("returns the error message for a regular Error", () => {
		const error = new Error("Something went wrong");
		expect(handleError(error)).toBe("Something went wrong");
	});

	it("returns the error message for errors with non-array columns", () => {
		const error = Object.assign(new Error("some error"), { columns: "email" });
		expect(handleError(error)).toBe("some error");
	});

	it("returns a friendly message for UniqueViolationError with one column", () => {
		const error = new Error("unique violation") as Error & {
			columns: string[];
		};
		error.columns = ["email"];
		Object.defineProperty(error, "constructor", {
			value: { name: "UniqueViolationError" },
		});
		expect(handleError(error)).toBe("email already exists.");
	});

	it("returns a friendly message for UniqueViolationError with multiple columns", () => {
		const error = new Error("unique violation") as Error & {
			columns: string[];
		};
		error.columns = ["username", "email"];
		Object.defineProperty(error, "constructor", {
			value: { name: "UniqueViolationError" },
		});
		expect(handleError(error)).toBe("username, email already exists.");
	});
});
