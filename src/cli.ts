#!/usr/bin/env node

// Dependencies
import { cancel, confirm, intro, isCancel, outro } from "@clack/prompts";
import { generateWizardApp } from "./generators/wizard/generateWizardApp.js";
import type { WizardSelections } from "./generators/wizard/types.js";

const usage = `Usage: fastify-auth wizard [--output <dir>] [--force]

  wizard    Interactively choose login methods (password, magic-link,
            optional TOTP MFA, forgotten-password) and generate a working
            combined auth setup - model stubs and a routes/auth.ts file
            built on @anephenix/fastify-auth/core.

Options:
  --output <dir>   Directory to generate files under (default: src)
  --force          Overwrite existing generated files (index.ts is never
                    overwritten)
`;

type ParsedArgs = {
	outputDir: string;
	force: boolean;
};

function parseArgs(argv: Array<string>): ParsedArgs | null {
	const [command, ...rest] = argv;
	if (command !== "wizard") return null;

	let outputDir = "src";
	let force = false;
	for (let i = 0; i < rest.length; i++) {
		if (rest[i] === "--output") {
			outputDir = rest[i + 1] ?? outputDir;
			i++;
		} else if (rest[i] === "--force") {
			force = true;
		}
	}
	return { outputDir, force };
}

function bail(): never {
	cancel("Cancelled.");
	process.exit(1);
}

async function askConfirm(
	message: string,
	initialValue: boolean,
): Promise<boolean> {
	const answer = await confirm({ message, initialValue });
	if (isCancel(answer)) bail();
	return answer;
}

async function runWizard(outputDir: string, force: boolean): Promise<void> {
	intro("fastify-auth wizard");

	const password = await askConfirm("Support password login?", true);
	const magicLink = await askConfirm("Support magic-link login?", false);

	if (!password && !magicLink) {
		cancel("Nothing to generate - choose at least one login method.");
		process.exit(1);
	}

	const totp = await askConfirm(
		"Add optional per-user TOTP MFA on top?",
		false,
	);

	const forgotPassword = password
		? await askConfirm("Add forgotten-password support?", true)
		: false;

	const selections: WizardSelections = {
		password,
		magicLink,
		totp,
		forgotPassword,
	};

	const result = generateWizardApp({ selections, outputDir, force });

	for (const file of result.files) {
		const label =
			file.action === "created" ? "created" : "skipped (already exists)";
		console.log(`  ${label}: ${file.path}`);
	}

	if (result.indexWiringInstructions) {
		console.log(
			`\nAn index.ts already exists under ${outputDir} - add these lines to wire up the generated auth routes:\n\n${result.indexWiringInstructions}\n`,
		);
	}

	if (totp) {
		console.log(
			"\nTOTP MFA needs two extra dependencies: npm i otplib qrcode\n" +
				"Also set TOTP_SECRET_ENCRYPTION_KEY in your environment - see lib/auth.ts.",
		);
	}

	outro("Done.");
}

function main(argv: Array<string>): void {
	const parsed = parseArgs(argv);
	if (!parsed) {
		console.log(usage);
		process.exitCode = 1;
		return;
	}

	runWizard(parsed.outputDir, parsed.force).catch((error) => {
		console.error(error);
		process.exitCode = 1;
	});
}

main(process.argv.slice(2));
