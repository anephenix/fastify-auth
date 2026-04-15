/**
 * Converts an error into a safe, user-facing string.
 *
 * Detects Objection.js UniqueViolationError by duck-typing (no hard dep on
 * objection) so the plugin stays ORM-agnostic while still producing friendly
 * messages for the most common constraint violation.
 */
export function handleError(error: Error): string {
	if (
		error &&
		Array.isArray((error as { columns?: unknown }).columns) &&
		error.constructor?.name === "UniqueViolationError"
	) {
		const columns = (error as unknown as { columns: string[] }).columns;
		return `${columns.join(", ")} already exists.`;
	}
	return error.message;
}
