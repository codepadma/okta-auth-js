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


import { FlowMonitor } from './FlowMonitor';

export class AccountUnlockFlowMonitor extends FlowMonitor {
  /* eslint complexity: [2, 15] */
  isRemediatorCandidate(remediator, remediations?, values?) {
    const prevRemediatorName = this.previousRemediator?.getName();
    const remediatorName = remediator.getName();

    // required to prevent /identify from auto-remediating when 'username' passed
    if (remediatorName === 'identify' && !prevRemediatorName) {
      return false;
    }

    if (remediatorName === 'unlock-account'
      && [
        'select-authenticator-unlock-account',
        'select-authenticator-authenticate',
        'challenge-authenticator'
      ].includes(prevRemediatorName)) {
      return false;
    }

    if (remediatorName === 'select-authenticator-authenticate' 
      && [
        'unlock-account',
        // 'select-authenticator-unlock-account',
        'challenge-authenticator',
        'select-authenticator-authenticate'
      ].includes(prevRemediatorName)) {
      return false;
    }

    if (remediatorName === 'select-authenticator-unlock-account'
      && [
        'identify',
        'select-authenticator-authenticate',
        'challenge-authenticator'
      ].includes(prevRemediatorName)) {
      return false;
    }

    if (remediatorName === 'challenge-authenticator' 
      && [
        'identify',
        'unlock-account'
      ].includes(prevRemediatorName)) {
      return false;
    }

    if (remediatorName === 'authenticator-verification-data' 
      && [
        'identify',
        'unlock-account',
        'challenge-authenticator'
      ].includes(prevRemediatorName)) {
      return false;
    }

    // TODO: maybe?
    if (remediatorName === 'select-authenticator-authenticate'
      && remediations.some(({ name }) => name === 'challenge-authenticator')) {
      return false;
    }

    return super.isRemediatorCandidate(remediator, remediations, values);
  }
}
