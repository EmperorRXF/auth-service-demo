/* eslint-disable @typescript-eslint/camelcase */
import axios from 'axios';
import * as cookieParser from 'cookie-parser';
import * as express from 'express';
import * as helmet from 'helmet';
import { Client, generators, Issuer, TokenSet } from 'openid-client';
import { config, getLogger } from './common';

const logger = getLogger('bootstrap');

let state: string;
let code_verifier: string;

async function getClient(): Promise<Client> {
  const issuer = new Issuer({
    issuer: 'github',
    authorization_endpoint: process.env.GITHUB_AUTHORIZATION_ENDPOINT_URL,
    token_endpoint: process.env.GITHUB_TOKEN_ENDPOINT_URL,
  });

  const client = new issuer.Client({
    client_id: process.env.GITHUB_CLIENT_ID,
    client_secret: process.env.GITHUB_CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/auth-callback'],
    response_types: ['code'],
  });

  return client;
}

async function getUserInfo(
  tokenSet: TokenSet,
): Promise<{ email: string; name: string; picture: string }> {
  // Get public user profile
  const userResponse = await axios.get(process.env.GITHUB_USER_ENDPOINT_URL, {
    headers: {
      Authorization: `token ${tokenSet.access_token}`,
    },
  });

  // Get public user email (not always public, depends if user decided to exclude email from public profile)
  const emailDataResponse = await axios.get(
    `${process.env.GITHUB_USER_ENDPOINT_URL}/emails`,
    {
      headers: {
        Authorization: `token ${tokenSet.access_token}`,
      },
    },
  );

  return {
    name: userResponse.data.name,
    email: emailDataResponse.data
      .filter((emailData) => emailData.primary == true)
      .map((emailData) => emailData.email)[0],
    picture: userResponse.data.avatar_url,
  };
}

export async function setupOAuthDemo(): Promise<void> {
  const app = express().use(helmet()).use(cookieParser());

  app.get('/', async (req, res) => {
    try {
      const client = await getClient();

      state = generators.state();
      code_verifier = generators.codeVerifier();

      const code_challenge = generators.codeChallenge(code_verifier);

      const authorizationUrl = client.authorizationUrl({
        scope: 'user',
        state,
        code_challenge,
        code_challenge_method: 'S256',
      });

      let pageHtml = `
        <a href=${authorizationUrl}>Login with GitHub</a>
        <br /><br /><br />
        <h3>Authorization URL</h3>
        <p>${authorizationUrl}</p>
      `;

      const oAuthSession = req.cookies['oauth_demo_session'];
      if (oAuthSession) {
        const user = JSON.parse(oAuthSession) as Record<string, unknown>;

        pageHtml += `
          <br />
          <h3>Session Cookie</h3>
          <p>${oAuthSession}</p>
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
      const tokenSet = await client.oauthCallback(
        'http://localhost:3000/auth-callback',
        params,
        {
          state,
          code_verifier,
        },
      );

      const oAuthSession = await getUserInfo(tokenSet);

      res.cookie('oauth_demo_session', JSON.stringify(oAuthSession), {
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
      res.clearCookie('oauth_demo_session');
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
