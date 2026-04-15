import { describe, expect, it } from "vitest";
import type { FastifyRequest } from "fastify";
import { detectClientType } from "../../src/helpers/detect-client-type.js";

function makeRequest(headers: Record<string, string>): FastifyRequest {
	return { headers } as unknown as FastifyRequest;
}

describe("detectClientType", () => {
	it('returns "web" when x-client-type header is "web"', () => {
		const req = makeRequest({ "x-client-type": "web" });
		expect(detectClientType(req)).toBe("web");
	});

	it('returns "web" when accept header includes text/html', () => {
		const req = makeRequest({ accept: "text/html,application/xhtml+xml" });
		expect(detectClientType(req)).toBe("web");
	});

	it('returns "web" when x-client-type is "web" even if accept is JSON', () => {
		const req = makeRequest({
			"x-client-type": "web",
			accept: "application/json",
		});
		expect(detectClientType(req)).toBe("web");
	});

	it('returns "api" when no relevant headers are present', () => {
		const req = makeRequest({});
		expect(detectClientType(req)).toBe("api");
	});

	it('returns "api" when accept is application/json', () => {
		const req = makeRequest({ accept: "application/json" });
		expect(detectClientType(req)).toBe("api");
	});

	it('returns "api" when x-client-type is "api"', () => {
		const req = makeRequest({ "x-client-type": "api" });
		expect(detectClientType(req)).toBe("api");
	});
});
