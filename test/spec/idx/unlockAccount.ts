/*!
 * Copyright (c) 2015-present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and limitations under the License.
 */


import { unlockAccount } from '../../../lib/idx/unlockAccount';
import { IdxStatus, AuthenticatorKey } from '../../../lib/idx/types';
import { AuthSdkError } from '../../../lib/errors';

import {
  chainResponses,
  IdxResponseFactory,
  RawIdxResponseFactory,
  IdxMessagesFactory,
  IdentifyRemediationFactory,
  UnlockAccountRemediationFactory,
  SelectAuthenticatorUnlockAccountRemediationFactory,
  SelectAuthenticatorAuthenticateRemediationFactory,
  ChallengeAuthenticatorRemediationFactory,
  AuthenticatorValueFactory,
  UsernameValueFactory,
  VerifyEmailRemediationFactory,
  VerifyEmailResponseFactory,
  VerifyPasscodeValueFactor,
  // AuthenticatorValueFactory,
  // OktaVerifyAuthenticatorOptionFactory,
  PhoneAuthenticatorOptionFactory,
  EmailAuthenticatorOptionFactory,
  // PasswordAuthenticatorVerificationDataRemediationFactory
} from '@okta/test.support/idx';

const mocked = {
  interact: require('../../../lib/idx/interact'),
  introspect: require('../../../lib/idx/introspect'),
  startTransaction: require('../../../lib/idx/startTransaction')
};

describe('/idx/unlockAccout', () => {
  let testContext;

  beforeEach(() => {
    const issuer = 'https://test-issuer';
    const clientId = 'test-clientId';
    const redirectUri = 'test-redirectUri';
    const transactionMeta = {
      issuer,
      clientId,
      redirectUri,
      interactionHandle: 'meta-interactionHandle',
      state: 'meta-state',
      codeVerifier: 'meta-code',
      scopes: ['meta'],
      urls: { authorizeUrl: 'meta-authorizeUrl' },
      ignoreSignature: true
    };
    const tokenResponse = {
      tokens: {
        fakeToken: true
      }
    };
    const authClient = {
      options: {
        issuer,
        clientId,
        redirectUri
      },
      transactionManager: {
        exists: () => true,
        load: () => transactionMeta,
        clear: () => {},
        save: () => {},
        saveIdxResponse: () => {},
        loadIdxResponse: () => {}
      },
      token: {
        exchangeCodeForTokens: () => Promise.resolve(tokenResponse)
      },
      idx: {
        setFlow: () => {}
      }
    };

    jest.spyOn(mocked.interact, 'interact').mockResolvedValue({ 
      meta: transactionMeta,
      interactionHandle: transactionMeta.interactionHandle,
      state: transactionMeta.state
    });

    // introspect
    const introspectResponse = IdxResponseFactory.build({
      neededToProceed: [
        UnlockAccountRemediationFactory.build()
      ]
    });

    // unlock-account
    const unlockAccoutRemediationResponse = IdxResponseFactory.build({
      neededToProceed: [
        SelectAuthenticatorUnlockAccountRemediationFactory.build({
          value: [
            UsernameValueFactory.build(),
            AuthenticatorValueFactory.build({
              options: [
                PhoneAuthenticatorOptionFactory.build(),
                EmailAuthenticatorOptionFactory.build(),
              ]
            })
          ]
        }),
      ]
    });

    // select-authenticator-authenticate
    const selectAuthRem = SelectAuthenticatorAuthenticateRemediationFactory.build({
      value: [
        AuthenticatorValueFactory.build({
          options: [
            PhoneAuthenticatorOptionFactory.build(),
            EmailAuthenticatorOptionFactory.build(),
          ]
        })
      ]
    })

    const identifyResponse = IdxResponseFactory.build({
      neededToProceed: [
        SelectAuthenticatorAuthenticateRemediationFactory.build({
          value: [
            AuthenticatorValueFactory.build({
              options: [
                PhoneAuthenticatorOptionFactory.build(),
                EmailAuthenticatorOptionFactory.build(),
              ]
            })
          ]
        }),
      ]
    });

    // account reset response
    const accountResetTerminalResponse = RawIdxResponseFactory.build({
      messages: IdxMessagesFactory.build({
        value: [
          {
            "message": "Your account is now unlocked!",
            "i18n": {
                "key": "selfservice.unlock_user.success.message",
                "params": []
            },
            "class": "INFO"
          }
        ]
      })
    });

    testContext = {
      authClient,
      transactionMeta,
      introspectResponse,
      unlockAccoutRemediationResponse,
      identifyResponse,
      accountResetTerminalResponse,
      selectAuthRem
    };
  });

  describe('feature detection', () => {

    it('throws an error if self service account unlock is not supported', async () => {
      const { authClient, transactionMeta } = testContext;
      jest.spyOn(authClient.transactionManager, 'exists').mockReturnValue(false);
      authClient.token.prepareTokenParams = jest.fn().mockResolvedValue(transactionMeta);
      const identifyResponse = IdxResponseFactory.build({
        neededToProceed: [
          IdentifyRemediationFactory.build(),
          // does not contain unlock-account
        ]
      });
      jest.spyOn(mocked.introspect, 'introspect').mockResolvedValue(identifyResponse);
      const res = await unlockAccount(authClient, {});
      expect(res.status).toBe(IdxStatus.FAILURE);
      expect(res.error).toBeInstanceOf(AuthSdkError);
      expect(res.error.errorSummary).toBe('Self Service Account Unlock is not supported based on your current org configuration.');
    });

    it('calls startTransaction, setting flow to "unlockAccount"', async () => {
      const { authClient } = testContext;
      jest.spyOn(authClient.transactionManager, 'exists').mockReturnValue(false);
      jest.spyOn(mocked.startTransaction, 'startTransaction').mockReturnValue({ enabledFeatures: [] });
      const res = await unlockAccount(authClient, {});
      expect(res.status).toBe(IdxStatus.FAILURE);
      expect(res.error).toBeInstanceOf(AuthSdkError);
      expect(res.error.errorSummary).toBe('Self Service Account Unlock is not supported based on your current org configuration.');
      expect(mocked.startTransaction.startTransaction).toHaveBeenCalledWith(authClient, { flow: 'unlockAccount' });
    });

    it('returns a transaction', async () => {
      const { 
        authClient,
        introspectResponse,
        unlockAccoutRemediationResponse
      } = testContext;
  
      chainResponses([
        introspectResponse,
        unlockAccoutRemediationResponse
      ]);
  
      jest.spyOn(mocked.introspect, 'introspect')
        .mockResolvedValueOnce(introspectResponse)
        .mockResolvedValueOnce(unlockAccoutRemediationResponse)
      
      jest.spyOn(introspectResponse, 'proceed');
      jest.spyOn(unlockAccoutRemediationResponse, 'proceed');
  
      let res = await unlockAccount(authClient, {});
      expect(introspectResponse.proceed).toHaveBeenCalledWith('unlock-account', { });
      expect(res).toMatchObject({
        _idxResponse: expect.any(Object),
        status: IdxStatus.PENDING,
        nextStep: {
          name: 'select-authenticator-unlock-account',
          inputs: [
            {
              key: 'string',
              name: 'authenticator'
            },
            {
              label: 'Username',
              name: 'username'
            }
          ],
          options: [
            {
              label: 'Phone',
              value: 'phone_number'
            },
            {
              label: 'Email',
              value: 'okta_email'
            }
          ],
        }
      });
    });
  });

  describe('email authenticator', () => {
    beforeEach(() => {
      const { 
        introspectResponse,
        unlockAccoutRemediationResponse,
        accountResetTerminalResponse,
        selectAuthRem
      } = testContext;

      const selectAuthenticatorUnlockAccountResponse = IdxResponseFactory.build({
        neededToProceed: [
          VerifyEmailRemediationFactory.build(),
          selectAuthRem,
        ]
      });
  
      const verifyEmailResponse = VerifyEmailResponseFactory.build();

      testContext = {
        ...testContext,
        selectAuthenticatorUnlockAccountResponse,
        verifyEmailResponse
      };

      chainResponses([
        introspectResponse,
        unlockAccoutRemediationResponse,
        selectAuthenticatorUnlockAccountResponse,
        verifyEmailResponse,
        accountResetTerminalResponse
      ]);
  
      jest.spyOn(mocked.introspect, 'introspect')
        .mockResolvedValueOnce(introspectResponse)
        .mockResolvedValueOnce(unlockAccoutRemediationResponse)
        .mockResolvedValueOnce(selectAuthenticatorUnlockAccountResponse)
        .mockResolvedValueOnce(verifyEmailResponse)
        .mockResolvedValueOnce(accountResetTerminalResponse);
      
      jest.spyOn(introspectResponse, 'proceed');
      jest.spyOn(unlockAccoutRemediationResponse, 'proceed');
      jest.spyOn(selectAuthenticatorUnlockAccountResponse, 'proceed');
      jest.spyOn(verifyEmailResponse, 'proceed');
    });

    xit('can proceed using username and email authenticator', async () => {
      const { 
        authClient,
        introspectResponse,
        unlockAccoutRemediationResponse,
        selectAuthenticatorUnlockAccountResponse,
        verifyEmailResponse
      } = testContext;
  
      let res = await unlockAccount(authClient, {});
      expect(introspectResponse.proceed).toHaveBeenCalledWith('unlock-account', {});
  
      const inputValues = {
        username: 'myname',
        authenticator: AuthenticatorKey.OKTA_EMAIL
      };
  
      res = await unlockAccount(authClient, inputValues);
      expect(unlockAccoutRemediationResponse.proceed).toHaveBeenCalledWith('select-authenticator-unlock-account', {
        identifier: 'myname',
        authenticator: {
          id: 'id-email'
        }
      });
      expect(res).toEqual({
        _idxResponse: expect.any(Object),
        status: IdxStatus.PENDING,
        nextStep: {
          name: 'challenge-authenticator',
          type: 'email',
          inputs: [
            {
              label: 'Enter code',
              name: 'verificationCode',
              required: true,
              type: 'string'
            }
          ],
          authenticator: {
            displayName: 'Email',
            id: '6',
            key: 'okta_email',
            methods: [{ type: 'email' }],
            type: 'email'
          }
        }
      });

      res = await unlockAccount(authClient, { verificationCode: 'test-passcode' });
      expect(selectAuthenticatorUnlockAccountResponse.proceed).toHaveBeenCalledWith('challenge-authenticator', {
        credentials: {
          passcode: 'test-passcode'
        }
      });
      expect(res).toEqual({
        _idxResponse: expect.any(Object),
        status: IdxStatus.TERMINAL,
      });
    });
  
    it('can auto-remediate using username and email authenticator', async () => {
      const { 
        authClient,
        introspectResponse,
        unlockAccoutRemediationResponse,
      } = testContext;

      const inputValues = {
        username: 'myname',
        authenticator: AuthenticatorKey.OKTA_EMAIL
      };
  
      let res = await unlockAccount(authClient, inputValues);
      expect(introspectResponse.proceed).toHaveBeenCalledWith('unlock-account', {});
      expect(unlockAccoutRemediationResponse.proceed).toHaveBeenCalledWith('select-authenticator-unlock-account', {
        identifier: 'myname',
        authenticator: {
          id: 'id-email'
        }
      });
      expect(res).toEqual({
        _idxResponse: expect.any(Object),
        status: IdxStatus.PENDING,
        nextStep: {
          name: 'challenge-authenticator',
          type: 'email',
          inputs: [
            {
              label: 'Enter code',
              name: 'verificationCode',
              required: true,
              type: 'string'
            }
          ],
          authenticator: {
            displayName: 'Email',
            id: '6',
            key: 'okta_email',
            methods: [{ type: 'email' }],
            type: 'email'
          }
        }
      });
    });
  });

});