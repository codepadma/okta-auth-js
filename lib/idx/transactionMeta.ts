/*!
 * Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import { OktaAuth, IdxTransactionMeta, TransactionMetaOptions } from '../types';
import { warn } from '../util';
import { getOAuthUrls } from '../oidc';

// Calculate new values
export async function createTransactionMeta(authClient: OktaAuth, options: TransactionMetaOptions = {}) {
  const tokenParams = await authClient.token.prepareTokenParams(options);
  const {
    clientId,
    redirectUri,
    responseType,
    responseMode,
    scopes,
    state,
    nonce,
    ignoreSignature,
    codeVerifier,
    codeChallengeMethod,
    codeChallenge,
  } = tokenParams;
  const urls = getOAuthUrls(authClient, tokenParams);
  let {
    flow = 'default',
    withCredentials = true,
    activationToken,
    recoveryToken
  } = { ...authClient.options, ...options }; // local options override SDK options
  const issuer = authClient.options.issuer;

  const meta: IdxTransactionMeta = {
    withCredentials,
    flow,
    issuer,
    clientId,
    redirectUri,
    responseType,
    responseMode,
    scopes,
    state,
    nonce,
    urls,
    ignoreSignature,
    codeVerifier,
    codeChallengeMethod,
    codeChallenge,
    activationToken,
    recoveryToken
  };
  return meta;
}

export function hasSavedInteractionHandle(authClient: OktaAuth, options?: TransactionMetaOptions): boolean {
  const savedMeta = getSavedTransactionMeta(authClient, options);
  if (savedMeta?.interactionHandle) {
    return true;
  }
  return false;
}

// Returns the saved transaction meta, if it exists and is valid
export function getSavedTransactionMeta(authClient: OktaAuth, options?: TransactionMetaOptions): IdxTransactionMeta {
  options = { ...authClient.options, ...options }; // local options override SDK options
  const savedMeta = authClient.transactionManager.load(options) as IdxTransactionMeta;
  if (savedMeta && isTransactionMetaValid(savedMeta, options)) {
    return savedMeta;
  }
}

export async function getTransactionMeta(
  authClient: OktaAuth,
  options?: TransactionMetaOptions
): Promise<IdxTransactionMeta> {
  options = { ...authClient.options, ...options }; // local options override SDK options
  // Load existing transaction meta from storage
  if (authClient.transactionManager.exists(options)) {
    const validExistingMeta = getSavedTransactionMeta(authClient, options);
    if (validExistingMeta) {
      return validExistingMeta;
    }
    // existing meta is not valid for this configuration
    // this is common when changing configuration in local development environment
    // in a production environment, this may indicate that two apps are sharing a storage key
    warn('Saved transaction meta does not match the current configuration. ' + 
      'This may indicate that two apps are sharing a storage key.');
  }

  return createTransactionMeta(authClient, options);
}

export function saveTransactionMeta (authClient: OktaAuth, meta): void {
  authClient.transactionManager.save(meta, { muteWarning: true });
}

export function clearTransactionMeta (authClient: OktaAuth): void {
  authClient.transactionManager.clear();
}

export function isTransactionMetaValid (meta, options: TransactionMetaOptions  = {}): boolean {
  // Validate against certain options. If these exist in options, they must match in meta
  const keys = [
    'issuer',
    'clientId',
    'redirectUri',
    'state',
    'codeChallenge',
    'codeChallengeMethod',
    'activationToken',
    'recoveryToken'
  ];
  if (isTransactionMetaValidForOptions(meta, options, keys) === false) {
    return false;
  }

  // Validate configured flow
  const { flow } = options;
  if (isTransactionMetaValidForFlow(meta, flow) === false) {
    return false;
  }

  return true;
}

export function isTransactionMetaValidForFlow(meta, flow) {
  // Specific flows should not share transaction data
  const shouldValidateFlow = flow && flow !== 'default' && flow !== 'proceed';
  if (shouldValidateFlow) {
    if (flow !== meta.flow) {
      // The flow has changed; abandon the old transaction
      return false;
    }
  }
  return true;
}

export function isTransactionMetaValidForOptions(meta, options, keys) {
  // returns false if values in meta do not match options
  // if the option does not have a value for a specific key, it is ignored
  const mismatch = keys.some(key => {
    const value = options[key];
    if (value && value !== meta[key]) {
      return true;
    }
  });
  return !mismatch;
}
