import { Authenticator } from './Authenticator';
import { RemediationValues } from '../remediators';

export interface OktaPasswordInputValues extends RemediationValues {
  password?: string;
}

export class OktaPassword extends Authenticator<OktaPasswordInputValues> {
  canVerify(values: OktaPasswordInputValues) {
    return !!values.password;
  }

  mapCredentials(values: OktaPasswordInputValues) {
    return { passcode: values.password };
  }

  getInputs(idxRemediationValue) {
    return {
      ...idxRemediationValue.form?.value[0],
      name: 'password',
      type: 'string',
      required: idxRemediationValue.required
    };
  }
}
