/*
 * Copyright 2022 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Config } from '@backstage/config';
import {
  ScmIntegrations,
  GithubIntegration,
  GithubAppConfig,
} from '@backstage/integration';
import {
  RequestDetails,
  RequestValidationContext,
  RequestValidator,
} from '@backstage/plugin-events-node';
import { verify } from '@octokit/webhooks-methods';

/**
 * Validates that the request received is the expected GitHub request
 * using the signature received with the `x-hub-signature-256` header
 * which is based on a secret token configured at GitHub and here.
 *
 * See https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks
 * for more details.
 *
 * @param config - root config
 * @public
 */
export function createGithubSignatureValidator(
  config: Config,
): RequestValidator {
  const { github } = ScmIntegrations.fromConfig(config);
  const apps = github
    .list()
    .flatMap((i: GithubIntegration) => i.config.apps || []);
  const secrets = apps.map((app: GithubAppConfig) => {
    if (!app.webhookSecret) {
      throw Error(
        `Missing required config value 'webhookSecret' for GitHub app ${app.appId}`,
      );
    }
    return app.webhookSecret!;
  });

  if (apps.length === 0 || config.has('events.modules.github.webhookSecret')) {
    secrets.push(config.getString('events.modules.github.webhookSecret'));
  }

  return async (
    request: RequestDetails,
    context: RequestValidationContext,
  ): Promise<void> => {
    const signature = request.headers['x-hub-signature-256'] as
      | string
      | undefined;

    // Verify if we have a signature header
    if (!signature) {
      context.reject({
        status: 403,
        payload: { message: 'missing signature' },
      });
      return;
    }

    // Try to verify the signature using any of the configured secrets
    const bodyString = request.raw.body.toString(request.raw.encoding);
    const isValidSignature = await Promise.any(
      secrets.map(async secret => {
        if (!(await verify(secret, bodyString, signature))) {
          throw new Error();
        }
        return true;
      }),
    ).catch(() => false);

    // Reject if no valid signature was found
    if (!isValidSignature) {
      context.reject({
        status: 403,
        payload: { message: 'invalid signature' },
      });
    }
  };
}
