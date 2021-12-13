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


import { OktaAuth } from '../../types';
import { getTransactionMeta, saveTransactionMeta } from '../transactionMeta';

export class FlowMonitor {
  previousStep: string;
  authClient: OktaAuth;

  constructor(authClient) {
    this.authClient = authClient;
  }

  // detect in-memory loop
  loopDetected(step: string): boolean {
    if (!this.previousStep) {
      this.previousStep = step;
      return false;
    }

    if (this.previousStep === step) {
      return true;
    }

    this.previousStep = step;
    return false;
  }

  async trackRemediations(name: string) {
    let meta = await getTransactionMeta(this.authClient);
    const remediations = meta.remediations || [];
    meta = { 
      ...meta, 
      remediations: [...remediations, name]
    };
    saveTransactionMeta(this.authClient, meta);
  }

  isFinished(): Promise<boolean> {
    return Promise.resolve(true);
  }
}
