const SsoProvider = require('../index');

describe('Testing getLogin', () => {
  test('with correct parameters', () => {
    let clientID = 123;
    let callbackUrl = 'http://mycallback';
    let scopes = ['scope1', 'scope2'];

    let sso = new SsoProvider(clientID);
    let login = sso.getLogin(callbackUrl, scopes);

    let expectedUrl = `https://login.eveonline.com/v2/oauth/authorize/?response_type=code&redirect_uri=${callbackUrl}&client_id=${clientID}&scope=${scopes[0]}%20${scopes[1]}&code_challenge=${sso._getEncodedCodeChallenge(login.clearCode)}&code_challenge_method=S256&state=${login.state}`

    expect(login.url).toBe(expectedUrl);
  });
});


