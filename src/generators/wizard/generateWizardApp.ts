// Dependencies
import fs from "node:fs";
import path from "node:path";
import { authLibTemplate } from "./authLibTemplate.js";
import { authRoutesTemplate } from "./authRoutesTemplate.js";
import { indexTemplate, indexWiringInstructions } from "./indexTemplate.js";
import {
	forgotPasswordModelTemplate,
	magicLinkModelTemplate,
	mfaTokenModelTemplate,
	recoveryCodeModelTemplate,
	sessionModelTemplate,
	userModelTemplate,
} from "./modelTemplates.js";
import type { WizardSelections } from "./types.js";

export type GenerateWizardAppOptions = {
	selections: WizardSelections;
	outputDir: string;
	force?: boolean;
};

export type GeneratedFile = {
	path: string;
	action: "created" | "skipped";
};

export type GenerateWizardAppResult = {
	files: Array<GeneratedFile>;
	// Present when outputDir/index.ts already existed - it's never
	// overwritten, so the wiring lines are returned instead.
	indexWiringInstructions?: string;
};

function writeFile(
	filePath: string,
	content: string,
	force: boolean,
): GeneratedFile {
	if (fs.existsSync(filePath) && !force) {
		return { path: filePath, action: "skipped" };
	}
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, content);
	return { path: filePath, action: "created" };
}

/*
  Scaffolds a combined auth setup under outputDir based on the wizard's
  selections - lib/auth.ts, one model per selected feature, routes/auth.ts,
  and index.ts (only if missing). Mirrors the skip-if-exists/force/never-
  overwrite-index behaviour of fastify-resource's generateResource().
*/
export function generateWizardApp({
	selections,
	outputDir,
	force = false,
}: GenerateWizardAppOptions): GenerateWizardAppResult {
	const files: Array<GeneratedFile> = [
		writeFile(
			path.join(outputDir, "lib", "auth.ts"),
			authLibTemplate(selections),
			force,
		),
		writeFile(
			path.join(outputDir, "models", "User.ts"),
			userModelTemplate(selections),
			force,
		),
		writeFile(
			path.join(outputDir, "models", "Session.ts"),
			sessionModelTemplate(),
			force,
		),
	];

	if (selections.magicLink) {
		files.push(
			writeFile(
				path.join(outputDir, "models", "MagicLink.ts"),
				magicLinkModelTemplate(),
				force,
			),
		);
	}

	if (selections.totp) {
		files.push(
			writeFile(
				path.join(outputDir, "models", "MfaToken.ts"),
				mfaTokenModelTemplate(),
				force,
			),
			writeFile(
				path.join(outputDir, "models", "RecoveryCode.ts"),
				recoveryCodeModelTemplate(),
				force,
			),
		);
	}

	if (selections.forgotPassword) {
		files.push(
			writeFile(
				path.join(outputDir, "models", "ForgotPassword.ts"),
				forgotPasswordModelTemplate(),
				force,
			),
		);
	}

	files.push(
		writeFile(
			path.join(outputDir, "routes", "auth.ts"),
			authRoutesTemplate(selections),
			force,
		),
	);

	const indexPath = path.join(outputDir, "index.ts");
	const result: GenerateWizardAppResult = { files };
	if (fs.existsSync(indexPath)) {
		result.indexWiringInstructions = indexWiringInstructions();
	} else {
		files.push(writeFile(indexPath, indexTemplate(), force));
	}

	return result;
}
