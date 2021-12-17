// const CLIENT_ID = process.env.SPA_CLIENT_ID || process.env.CLIENT_ID || '{clientId}';
// const ISSUER = process.env.ISSUER || 'https://{yourOktaDomain}.com/oauth2/default';
const REDIRECT_URI = `${window.location.origin}/login/callback`;

// eslint-disable-next-line import/no-anonymous-default-export
// export default {
//   clientId: CLIENT_ID,
//   issuer: ISSUER,
//   redirectUri: REDIRECT_URI,
//   scopes: ['openid', 'profile', 'email'],
//   pkce: true
// };

export default {
  clientId: '0oa1leqqr3siAxMqB1d7',
  issuer: 'https://jperreault-test.oktapreview.com/oauth2/default',
  redirectUri: REDIRECT_URI,
  scopes: ['openid', 'profile', 'email'],
  pkce: true
};