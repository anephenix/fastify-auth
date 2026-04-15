import type { FastifyRequest } from "fastify";

type ClientType = "web" | "api";

/**
 * Determines whether the request is coming from a web browser or an API client.
 *
 * Checks (in order):
 *  1. `x-client-type` header – explicit override ("web" | "api")
 *  2. `accept` header – "text/html" indicates a browser
 *  3. Falls back to "api"
 *
 * This drives whether successful login responses set cookies (web) or return
 * tokens in the JSON body (api).
 */
export function detectClientType(request: FastifyRequest): ClientType {
	const clientHeader = request.headers["x-client-type"];
	const acceptHeader = request.headers.accept ?? "";

	if (clientHeader === "web" || acceptHeader.includes("text/html")) {
		return "web";
	}

	return "api";
}
