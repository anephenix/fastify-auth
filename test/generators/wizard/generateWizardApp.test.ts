import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateWizardApp } from "../../../src/generators/wizard/generateWizardApp.js";
import type { WizardSelections } from "../../../src/generators/wizard/types.js";

const fullCombo: WizardSelections = {
	password: true,
	magicLink: true,
	totp: true,
	forgotPassword: true,
};

const passwordOnly: WizardSelections = {
	password: true,
	magicLink: false,
	totp: false,
	forgotPassword: false,
};

let tmpDir: string;

beforeEach(() => {
	tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fastify-auth-wizard-"));
});

afterEach(() => {
	fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("generateWizardApp", () => {
	it("creates lib/auth.ts, all models, routes/auth.ts and index.ts for the full combo", () => {
		const result = generateWizardApp({
			selections: fullCombo,
			outputDir: tmpDir,
		});

		const expectedPaths = [
			path.join(tmpDir, "lib", "auth.ts"),
			path.join(tmpDir, "models", "User.ts"),
			path.join(tmpDir, "models", "Session.ts"),
			path.join(tmpDir, "models", "MagicLink.ts"),
			path.join(tmpDir, "models", "MfaToken.ts"),
			path.join(tmpDir, "models", "RecoveryCode.ts"),
			path.join(tmpDir, "models", "ForgotPassword.ts"),
			path.join(tmpDir, "routes", "auth.ts"),
			path.join(tmpDir, "index.ts"),
		];
		for (const expectedPath of expectedPaths) {
			assert.ok(
				fs.existsSync(expectedPath),
				`expected ${expectedPath} to exist`,
			);
		}
		expect(result.files.every((f) => f.action === "created")).toBe(true);
		expect(result.indexWiringInstructions).toBeUndefined();
	});

	it("only creates the files relevant to a minimal (password-only) combo", () => {
		generateWizardApp({ selections: passwordOnly, outputDir: tmpDir });

		assert.ok(fs.existsSync(path.join(tmpDir, "models", "User.ts")));
		assert.ok(fs.existsSync(path.join(tmpDir, "models", "Session.ts")));
		assert.ok(!fs.existsSync(path.join(tmpDir, "models", "MagicLink.ts")));
		assert.ok(!fs.existsSync(path.join(tmpDir, "models", "MfaToken.ts")));
		assert.ok(!fs.existsSync(path.join(tmpDir, "models", "ForgotPassword.ts")));
	});

	it("skips existing files on a second run without force", () => {
		generateWizardApp({ selections: fullCombo, outputDir: tmpDir });
		const result = generateWizardApp({
			selections: fullCombo,
			outputDir: tmpDir,
		});

		const layerFiles = result.files.filter((f) => !f.path.endsWith("index.ts"));
		expect(layerFiles.every((f) => f.action === "skipped")).toBe(true);
	});

	it("overwrites existing files when force is set", () => {
		generateWizardApp({ selections: fullCombo, outputDir: tmpDir });
		const result = generateWizardApp({
			selections: fullCombo,
			outputDir: tmpDir,
			force: true,
		});

		const layerFiles = result.files.filter((f) => !f.path.endsWith("index.ts"));
		expect(layerFiles.every((f) => f.action === "created")).toBe(true);
	});

	it("never overwrites an existing index.ts, returning wiring instructions instead", () => {
		generateWizardApp({ selections: fullCombo, outputDir: tmpDir });
		const indexPath = path.join(tmpDir, "index.ts");
		const originalIndexContent = fs.readFileSync(indexPath, "utf8");

		const result = generateWizardApp({
			selections: fullCombo,
			outputDir: tmpDir,
			force: true,
		});

		expect(fs.readFileSync(indexPath, "utf8")).toBe(originalIndexContent);
		expect(result.indexWiringInstructions).toContain("registerAuthRoutes");
		expect(result.files.some((f) => f.path === indexPath)).toBe(false);
	});
});
