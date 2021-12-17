import { Authenticator } from './Authenticator';
import { RemediationValues } from '../remediators';

export interface SecurityQuestionVerificationValues extends RemediationValues {
  answer?: string;
}

export class SecurityQuestionVerification extends Authenticator<SecurityQuestionVerificationValues> {
  canVerify(values: SecurityQuestionVerificationValues) {
    return !!values.answer;
  }

  mapCredentials(values: SecurityQuestionVerificationValues) {
    return {
      questionKey: this.meta.contextualData.enrolledQuestion.questionKey,
      answer: values.answer
    };
  }

  getInputs() {
    return [
      { name: 'answer', type: 'string', label: 'Answer', required: true }
    ];
  }
}
