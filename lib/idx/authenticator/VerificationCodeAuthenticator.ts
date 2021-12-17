import { Authenticator, Credentials } from './Authenticator';

export interface VerificationCodeValues {
  verificationCode?: string;
}

interface VerificationCodeCredentials extends Credentials {
  passcode: string;
}

// general authenticator to handle "verificationCode" input
// it can be used for "email", "phone", "google authenticator"
// a new authenticator class should be created if special cases need to be handled
export class VerificationCodeAuthenticator extends Authenticator<VerificationCodeValues> {
  canVerify(values: VerificationCodeValues) {
    return !!values.verificationCode;
  }

  mapCredentials(values: VerificationCodeValues): VerificationCodeCredentials | Credentials {
    return { passcode: values.verificationCode };
  }

  getInputs(idxRemediationValue) {
    return {
      ...idxRemediationValue.form?.value[0],
      name: 'verificationCode',
      type: 'string',
      required: idxRemediationValue.required
    };
  }
}
