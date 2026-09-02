/*
  Only used when outputDir/index.ts doesn't already exist - mirrors
  fastify-resource's generator, which never overwrites an existing index.ts
  since it may already register other things.
*/
export function indexTemplate(): string {
	return `import fastifyCookie from "@fastify/cookie";
import Fastify from "fastify";
import { registerAuthRoutes } from "./routes/auth.js";

const app = Fastify();

app.register(fastifyCookie);
registerAuthRoutes(app);

app.listen({ port: 3000 }, (err) => {
	if (err) {
		app.log.error(err);
		process.exit(1);
	}
});

export default app;
`;
}

export function indexWiringInstructions(): string {
	return 'import { registerAuthRoutes } from "./routes/auth.js";\nregisterAuthRoutes(app);';
}
