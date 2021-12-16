import { Authenticator } from './Authenticator';

export class WebauthnEnrollment extends Authenticator {
  canVerify(values) {
    const { clientData, attestation } = values;
    return (clientData && attestation);
  }

  mapCredentials(values) {
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
