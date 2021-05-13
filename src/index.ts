/* eslint-disable @typescript-eslint/camelcase */
import { setupOIDCDemo } from './oidc-client';
import { getLogger } from './common';
import { setupOAuthDemo } from './oauth-client';

const logger = getLogger('bootstrap');

async function bootstrap(): Promise<void> {
  // await setupOAuthDemo();
  await setupOIDCDemo();
}

bootstrap().catch((error) => {
  logger.error('An unhandled exception occurred', {
    error,
  });
  process.exit();
});
