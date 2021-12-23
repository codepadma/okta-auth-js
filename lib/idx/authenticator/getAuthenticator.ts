import { OktaVerifyTotp } from './OktaVerifyTotp';
import { Authenticator } from './Authenticator';
import { VerificationCodeAuthenticator } from './VerificationCodeAuthenticator';
import { OktaPassword } from './OktaPassword';
import { SecurityQuestionEnrollment } from './SecurityQuestionEnrollment';
import { SecurityQuestionVerification } from './SecurityQuestionVerification';
import { WebauthnEnrollment } from './WebauthnEnrollment';
import { WebauthnVerification } from './WebauthnVerification';
import { IdxRemediation } from '../types/idx-js';
import { AuthenticatorKey } from '../types';

export function getAuthenticator(remediation: IdxRemediation): Authenticator {
  const { relatesTo: { value } = {} } = remediation;
  switch (value.key) {
    case AuthenticatorKey.OKTA_PASSWORD:
      return new OktaPassword(value);
    case AuthenticatorKey.SECURITY_QUESTION:
      if (value.contextualData.enrolledQuestion) {
        return new SecurityQuestionVerification(value);
      } else {
        return new SecurityQuestionEnrollment(value);
      }
    case AuthenticatorKey.OKTA_VERIFY:
      return new OktaVerifyTotp(value);
    case AuthenticatorKey.WEBAUTHN:
      if (value.contextualData.challengeData) {
        return new WebauthnVerification(value);
      } else {
        return new WebauthnEnrollment(value);
      }
    default:
      return new VerificationCodeAuthenticator(value);
  }
}
