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


import { run } from '../../../lib/idx/run';
import { IdxStatus } from '../../../lib/idx/types';
import { IdxResponseFactory } from '@okta/test.support/idx';
import { AuthSdkError } from '../../../lib/errors';

jest.mock('../../../lib/idx/transactionMeta', () => {
  return {
    getSavedTransactionMeta: () => {}
  };
});

const mocked = {
  interact: require('../../../lib/idx/interact'),
  introspect: require('../../../lib/idx/introspect'),
  remediate: require('../../../lib/idx/remediate'),
  transactionMeta: require('../../../lib/idx/transactionMeta'),
  FlowSpecification: require('../../../lib/idx/flow/FlowSpecification')
};

describe('idx/run', () => {
  let testContext;
  beforeEach(() => {
    const transactionMeta = {
      state: 'meta-state',
      codeVerifier: 'meta-code',
      clientId: 'meta-clientId',
      redirectUri: 'meta-redirectUri',
      scopes: ['meta'],
      urls: { authorizeUrl: 'meta-authorizeUrl' },
      ignoreSignature: true
    };
    jest.spyOn(mocked.interact, 'interact').mockResolvedValue({ 
      meta: transactionMeta,
      interactionHandle: 'meta-interactionHandle',
      state: transactionMeta.state
    });

    const idxResponse = IdxResponseFactory.build();
    jest.spyOn(mocked.introspect, 'introspect').mockResolvedValue(idxResponse);

    const remediateResponse = {
      idxResponse,
      nextStep: 'remediate-nextStep',
      messages: undefined,
      terminal: false
    };
    jest.spyOn(mocked.remediate, 'remediate').mockResolvedValue(remediateResponse);

    const tokenResponse = {
      tokens: {
        fakeToken: true
      }
    };
    const authClient = {
      transactionManager: {
        load: () => transactionMeta,
        clear: () => {},
        saveIdxResponse: () => {},
        clearIdxResponse: () => {}
      },
      token: {
        exchangeCodeForTokens: () => Promise.resolve(tokenResponse)
      },
      options: {},
      idx: {
        setFlow: () => {},
        getFlow: () => {}
      }
    };

    const interactOptions = {
      withCredentials: false,
      state: 'abc',
      scopes: ['fooboo']
    };

    testContext = {
      idxResponse,
      remediateResponse,
      tokenResponse,
      transactionMeta,
      authClient,
      interactOptions
    };
  });

  describe('flow', () => {
    it('if not specified or already set, sets the flow to "default"', async () => {
      const { authClient } = testContext;
      jest.spyOn(authClient.idx, 'setFlow');
      await run(authClient);
      expect(authClient.idx.setFlow).toHaveBeenCalledWith('default');
    });
  
    it('if flow is set in run options, it sets the flow on the authClient', async () => {
      const { authClient } = testContext;
      const flow = 'signup';
      jest.spyOn(authClient.idx, 'setFlow');
      await run(authClient, { flow });
      expect(authClient.idx.setFlow).toHaveBeenCalledWith(flow);
    });

    it('if flow is not set in run options, it respects the flow already set on auth client', async () => {
      const { authClient } = testContext;
      jest.spyOn(authClient.idx, 'getFlow').mockReturnValue('existing');
      jest.spyOn(authClient.idx, 'setFlow');
      await run(authClient);
      expect(authClient.idx.setFlow).toHaveBeenCalledWith('existing');
    });

    it('retrieves flow specification based on flow option', async () => {
      const { authClient } = testContext;
      jest.spyOn(mocked.FlowSpecification, 'getFlowSpecification');
      await run(authClient, { flow: 'signup' });
      expect(mocked.FlowSpecification.getFlowSpecification).toHaveBeenCalledWith(authClient, 'signup');
    });

    it('retrieves flow specification based on flow option', async () => {
      const { authClient } = testContext;
      jest.spyOn(mocked.FlowSpecification, 'getFlowSpecification');
      await run(authClient, { flow: 'signup' });
      expect(mocked.FlowSpecification.getFlowSpecification).toHaveBeenCalledWith(authClient, 'signup');
    });
  });

  describe('with saved transaction', () => {
    beforeEach(() => {
      const { transactionMeta } = testContext;
      jest.spyOn(mocked.transactionMeta, 'getSavedTransactionMeta').mockReturnValue(transactionMeta);
    });
    it('if saved meta has no interactionHandle, will call interact', async () => {
      const { authClient } = testContext;
      await run(authClient);
      expect(mocked.interact.interact).toHaveBeenCalled();
    });
    it('if saved meta has interactionHandle, does not call interact', async () => {
      const { authClient, transactionMeta } = testContext;
      transactionMeta.interactionHandle = 'fake';
      await run(authClient);
      expect(mocked.interact.interact).not.toHaveBeenCalled();
    });
  });

  describe('no saved transaction', () => {
    beforeEach(() => {
      jest.spyOn(mocked.transactionMeta, 'getSavedTransactionMeta').mockReturnValue(undefined);
    });
    it('clears saved transaction data and calls interact', async () => {
      const { authClient } = testContext;
      jest.spyOn(authClient.transactionManager, 'clear');
      await run(authClient);
      expect(authClient.transactionManager.clear).toHaveBeenCalledTimes(1);
      expect(mocked.interact.interact).toHaveBeenCalled();
    });
  });

  it('returns transaction', async () => {
    const { authClient } = testContext;
    const res = await run(authClient);
    expect(res).toMatchObject({
      status: IdxStatus.PENDING,
      nextStep: 'remediate-nextStep',
    });
  });

  it('calls interact, passing options through', async () => {
    const { authClient, interactOptions } = testContext;
    await run(authClient, interactOptions);
    expect(mocked.interact.interact).toHaveBeenCalledWith(authClient, interactOptions);
  });

  it('calls introspect with interactionHandle', async () => {
    const { authClient } = testContext;
    await run(authClient);
    expect(mocked.introspect.introspect).toHaveBeenCalledWith(authClient, { 
      interactionHandle: 'meta-interactionHandle'
    });
  });

  it('calls remediate, passing options and values through', async () => {
    const { authClient, idxResponse } = testContext;
    const options = { username: 'x' };
    const values = { 
      ...options, 
      stateHandle: idxResponse.rawIdxState.stateHandle 
    };
    const flowSpec = mocked.FlowSpecification.getFlowSpecification(authClient);
    const { remediators, actions, flowMonitor } = flowSpec;
    await run(authClient, options);
    expect(mocked.remediate.remediate).toHaveBeenCalledWith(idxResponse, values, { remediators, actions, flowMonitor });
  });

  it('saves idxResponse when nextStep is avaiable', async () => {
    const { authClient, idxResponse, remediateResponse } = testContext;
    remediateResponse.nextStep = 'has-next-step';
    jest.spyOn(authClient.transactionManager, 'saveIdxResponse');
    await run(authClient);
    expect(authClient.transactionManager.saveIdxResponse).toHaveBeenCalledWith(idxResponse.rawIdxState);
  });

  it('returns messages in transaction', async () => {
    testContext.remediateResponse.messages = ['remediate-message-1'];
    const { authClient } = testContext;
    const res = await run(authClient);
    expect(res).toMatchObject({
      messages: ['remediate-message-1'],
      nextStep: 'remediate-nextStep',
      status: IdxStatus.PENDING,
    });
  });

  describe('response is not terminal', () => {
    beforeEach(() => {
      const { remediateResponse, transactionMeta } = testContext;
      remediateResponse.terminal = false;
      // load from saved transaction
      transactionMeta.interactionHandle = 'fake';
      jest.spyOn(mocked.transactionMeta, 'getSavedTransactionMeta').mockReturnValue(transactionMeta);
    });

    it('does not clear transaction storage', async () => {
      const { authClient } = testContext;

      jest.spyOn(authClient.transactionManager, 'clear');
      const res = await run(authClient);
      expect(authClient.transactionManager.clear).not.toHaveBeenCalledWith();
      expect(res).toMatchObject({
        nextStep: 'remediate-nextStep',
        status: IdxStatus.PENDING,
      });
    });
  });

  describe('response is terminal', () => {
    beforeEach(() => {
      const { remediateResponse, transactionMeta } = testContext;
      remediateResponse.terminal = true;
      // load from saved transaction
      transactionMeta.interactionHandle = 'fake';
      jest.spyOn(mocked.transactionMeta, 'getSavedTransactionMeta').mockReturnValue(transactionMeta);
    });

    it('clears transaction storage', async () => {
      const { authClient } = testContext;
      jest.spyOn(authClient.transactionManager, 'clear');
      const res = await run(authClient);
      expect(authClient.transactionManager.clear).toHaveBeenCalledTimes(1);
      expect(res).toMatchObject({
        nextStep: 'remediate-nextStep',
        status: IdxStatus.TERMINAL,
      });
    });
  });

  describe('response contains interactionCode', () => {
    beforeEach(() => {
      testContext.remediateResponse.idxResponse.interactionCode = 'idx-interactionCode';
    });

    it('calls exchangeCodeForTokens and returns tokens', async () => {
      const { authClient, tokenResponse } = testContext;

      jest.spyOn(authClient.transactionManager, 'load');
      jest.spyOn(authClient.transactionManager, 'clear');
      jest.spyOn(authClient.token, 'exchangeCodeForTokens');

      const res = await run(authClient);
      expect(authClient.transactionManager.clear).toHaveBeenCalledWith();
      expect(authClient.token.exchangeCodeForTokens).toHaveBeenCalledWith({
        'clientId': 'meta-clientId',
        'codeVerifier': 'meta-code',
        'ignoreSignature': true,
        'interactionCode': 'idx-interactionCode',
        'redirectUri': 'meta-redirectUri',
        'scopes': [
          'meta',
        ],
      },
      {
        'authorizeUrl': 'meta-authorizeUrl'
      });

      expect(res).toMatchObject({
        nextStep: 'remediate-nextStep',
        status: IdxStatus.SUCCESS,
        tokens: tokenResponse.tokens,
      });
    });

    it('catches error when the flow is not supposed to be finished', async () => {
      const { authClient } = testContext; 

      const flowMonitor = {
        isFinished: jest.fn().mockResolvedValue(false)
      };
      jest.spyOn(mocked.FlowSpecification, 'getFlowSpecification').mockReturnValue({ remediators: {}, actions: [], flowMonitor });

      jest.spyOn(authClient.transactionManager, 'load');
      jest.spyOn(authClient.transactionManager, 'clear');
      jest.spyOn(authClient.token, 'exchangeCodeForTokens');

      const res = await run(authClient);
      expect(authClient.transactionManager.clear).toHaveBeenCalledWith();
      expect(authClient.token.exchangeCodeForTokens).not.toHaveBeenCalledWith();
      expect(res.status).toEqual(IdxStatus.FAILURE);
      expect(res.error instanceof AuthSdkError).toBeTruthy();
      expect((res.error as AuthSdkError).message).toEqual('Current flow is not supported, check policy settings in your org.');
    });

    it('catches errors from exchangeCodeForTokens and clears storage', async () => {
      const { authClient } = testContext;
      const error = new Error('threw an error');

      jest.spyOn(authClient.transactionManager, 'load');
      jest.spyOn(authClient.transactionManager, 'clear');
      jest.spyOn(authClient.token, 'exchangeCodeForTokens').mockImplementation(async () => {
        throw error;
      });

      const res = await run(authClient);
      expect(authClient.transactionManager.clear).toHaveBeenCalledWith();
      expect(authClient.token.exchangeCodeForTokens).toHaveBeenCalledWith({
        'clientId': 'meta-clientId',
        'codeVerifier': 'meta-code',
        'ignoreSignature': true,
        'interactionCode': 'idx-interactionCode',
        'redirectUri': 'meta-redirectUri',
        'scopes': [
          'meta',
        ],
      },
      {
        'authorizeUrl': 'meta-authorizeUrl'
      });

      expect(res).toMatchObject({
        error,
        nextStep: 'remediate-nextStep',
        status: IdxStatus.FAILURE,
      });
    });
  });

});