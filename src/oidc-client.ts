/* eslint-disable @typescript-eslint/camelcase */
import * as cookieParser from 'cookie-parser';
import * as express from 'express';
import * as helmet from 'helmet';
import * as jwt from 'jsonwebtoken';
import { Client, generators, Issuer } from 'openid-client';
import { config, getLogger } from './common';

const logger = getLogger('bootstrap');

let state: string;
let nonce: string;
let code_verifier: string;

async function getClient(): Promise<Client> {
  const issuer = await Issuer.discover(
    process.env.GOOGLE_DISCOVERY_DOCUMENT_URL,
  );
  const client = new issuer.Client({
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/auth-callback'],
    response_types: ['code'],
  });

  return client;
}

export async function setupOIDCDemo(): Promise<void> {
  const app = express().use(helmet()).use(cookieParser());

  app.get('/', async (req, res) => {
    try {
      const client = await getClient();

      state = generators.state();
      nonce = generators.nonce();
      code_verifier = generators.codeVerifier();

      const code_challenge = generators.codeChallenge(code_verifier);

      const authorizationUrl = client.authorizationUrl({
        scope: 'openid email profile',
        state,
        nonce,
        code_challenge,
        code_challenge_method: 'S256',
        // access_type: 'offline',
      });

      let pageHtml = `
        <a href=${authorizationUrl}>Login with Google</a>
        <br /><br /><br />
        <h3>Authorization URL</h3>
        <p>${authorizationUrl}</p>
      `;

      const oidcDemoSession = req.cookies['oidc_demo_session'];
      if (oidcDemoSession) {
        const user = jwt.decode(oidcDemoSession) as Record<string, unknown>;

        pageHtml += `
          <br />
          <h3>Session Cookie</h3>
          <p>${oidcDemoSession}</p>
          <br />
          <b>Welcome, ${user.name} (${user.email})</b>
          <br />
          <img src=${user.picture}></img>
          <br />
          <button type="button" onclick="location.href='/sign-out'" >Sign Out</button>
        `;
      }

      res.send(pageHtml);
    } catch (error) {
      res.send({ error: error.message }).status(400);
      logger.error(error);
    }
  });

  app.get('/auth-callback', async (req, res) => {
    try {
      const client = await getClient();
      const params = client.callbackParams(req);
      const tokenSet = await client.callback(
        'http://localhost:3000/auth-callback',
        params,
        {
          state,
          nonce,
          code_verifier,
        },
      );

      console.log(tokenSet);

      res.cookie('oidc_demo_session', tokenSet.id_token, {
        httpOnly: true,
        maxAge: 1000 * 30, // 30 seconds
      });

      res.redirect('/');
    } catch (error) {
      res.send({ error: error.message }).status(400);
      logger.error(error);
    }
  });

  app.get('/sign-out', async (req, res) => {
    try {
      res.clearCookie('oidc_demo_session');
      res.redirect('/');
    } catch (error) {
      res.send({ error: error.message }).status(400);
      logger.error(error);
    }
  });

  app.listen(config.port, () => {
    if (config.isDev()) {
      logger.info('Application Running', {
        url: `http://localhost:${config.port}`,
      });
    }
  });
}
