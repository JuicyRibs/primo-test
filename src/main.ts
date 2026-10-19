import { createApp } from './app';

async function bootstrap(): Promise<void> {
  const port = Number(process.env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  const app = await createApp();
  await app.listen(port);
  console.log(`Service: http://localhost:${port}; Swagger: http://localhost:${port}/api-docs`);
}

bootstrap().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : 'Service failed to start.');
  process.exitCode = 1;
});
