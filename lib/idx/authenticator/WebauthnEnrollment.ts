import { Authenticator } from './Authenticator';
import { RemediationValues } from '../remediators';

export interface WebauthnEnrollValues extends RemediationValues {
  clientData?: string;
  attestation?: string;
}

export class WebauthnEnrollment extends Authenticator<WebauthnEnrollValues> {
  canVerify(values: WebauthnEnrollValues) {
    const { clientData, attestation } = values;
    return (!!clientData && !!attestation);
  }

  mapCredentials(values: WebauthnEnrollValues) {
    const { clientData, attestation } = values;
    return {
      clientData,
      attestation
    };
  }

  getInputs() {
    return [
      { name: 'clientData', type: 'string', required: true, visible: false, label: 'Client Data' },
      { name: 'attestation', type: 'string', required: true, visible: false, label: 'Attestation' },
    ];
  }
}
