/*
 * Copyright (c) 2018, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */


// Get known credentials from list of enrolled authenticators
const getEnrolledCredentials = (authenticatorEnrollments = []) => {
  const credentials = [];
  authenticatorEnrollments.forEach((enrollement) => {
    if (enrollement.key === 'webauthn') {
      credentials.push({
        type: 'public-key',
        id: OktaAuth.crypto.base64UrlToBuffer(enrollement.credentialId),
      });
    }
  });
  return credentials;
};

// Build options for navigator.credentials.create
// https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
const buildCredentialCreationOptions = (activationData, authenticatorEnrollments) => {
  return {
    publicKey: {
      rp: activationData.rp,
      user: {
        id: OktaAuth.crypto.base64UrlToBuffer(activationData.user.id),
        name: activationData.user.name,
        displayName: activationData.user.displayName
      },
      challenge: OktaAuth.crypto.base64UrlToBuffer(activationData.challenge),
      pubKeyCredParams: activationData.pubKeyCredParams,
      attestation: activationData.attestation,
      authenticatorSelection: activationData.authenticatorSelection,
      excludeCredentials: getEnrolledCredentials(authenticatorEnrollments),
    }
  };
};

// Build options for navigator.credentials.get
// https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
const buildCredentialRequestOptions = (challengeData, authenticatorEnrollments) => {
  return {
    publicKey: {
      challenge: OktaAuth.crypto.base64UrlToBuffer(challengeData.challenge),
      userVerification: challengeData.userVerification,
      allowCredentials: getEnrolledCredentials(authenticatorEnrollments),
    }
  };
};

// credential is AuthenticatorAttestationResponse
// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
const getAttestation = (credential) => {
  const id = credential.id;
  const clientData = OktaAuth.crypto.bufferToBase64Url(credential.response.clientDataJSON);
  const attestation = OktaAuth.crypto.bufferToBase64Url(credential.response.attestationObject);
  return {
    id,
    clientData,
    attestation
  };
};

// credential is AuthenticatorAssertionResponse
// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
const getAssertion = (credential) => {
  const id = credential.id;
  const clientData = OktaAuth.crypto.bufferToBase64Url(credential.response.clientDataJSON);
  const authenticatorData = OktaAuth.crypto.bufferToBase64Url(credential.response.authenticatorData);
  const signatureData = OktaAuth.crypto.bufferToBase64Url(credential.response.signature);
  return {
    id,
    clientData,
    authenticatorData,
    signatureData
  };
};

// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
const CredentialsContainer = navigator.credentials;

Object.assign(window, {
  buildCredentialCreationOptions,
  buildCredentialRequestOptions,
  getAttestation,
  getAssertion,
  CredentialsContainer
});