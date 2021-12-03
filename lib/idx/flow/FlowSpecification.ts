import { OktaAuth, FlowIdentifier } from '../../types';
import { AuthenticationFlow } from './AuthenticationFlow';
import { AuthenticationFlowMonitor } from './AuthenticationFlowMonitor';
import { FlowMonitor } from './FlowMonitor';
import { PasswordRecoveryFlow } from './PasswordRecoveryFlow';
import { PasswordRecoveryFlowMonitor } from './PasswordRecoveryFlowMonitor';
import { RegistrationFlow } from './RegistrationFlow';
import { RegistrationFlowMonitor } from './RegistrationFlowMonitor';
import { RemediationFlow } from './RemediationFlow';

export interface FlowSpecification {
  flow: FlowIdentifier;
  remediators: RemediationFlow;
  flowMonitor: FlowMonitor;
  actions?: string[];
  withCredentials?: boolean;
}

export function getFlowSpecification(oktaAuth: OktaAuth, flow: FlowIdentifier = 'default'): FlowSpecification {
  let remediators, flowMonitor, actions, withCredentials = true;
  switch (flow) {
    case 'register':
    case 'signup':
    case 'enrollProfile':
      remediators = RegistrationFlow;
      flowMonitor = new RegistrationFlowMonitor(oktaAuth);
      withCredentials = false;
      break;
    case 'recoverPassword':
    case 'resetPassword':
      remediators = PasswordRecoveryFlow;
      flowMonitor = new PasswordRecoveryFlowMonitor(oktaAuth);
      actions = [
        'currentAuthenticator-recover', 
        'currentAuthenticatorEnrollment-recover'
      ];
      withCredentials = false;
      break;
    default:
      // authenticate
      remediators = AuthenticationFlow;
      flowMonitor = new AuthenticationFlowMonitor(oktaAuth);
      break;
  }
  return { flow, remediators, flowMonitor, actions, withCredentials };
}
