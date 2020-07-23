const WordArray = require("crypto-js/lib-typedarrays");
const Base64 = require("crypto-js/enc-base64");
const { encode, trim } = require("url-safe-base64");
const sha256 = require("crypto-js/sha256");
const Url = require("url-parse");
const jwt = require("jsonwebtoken");
const JwksRsa = require("jwks-rsa");


const LOGIN_URI = 'https://login.eveonline.com/v2/oauth/authorize';
const TOKEN_URI = 'https://login.eveonline.com/v2/oauth/token';
const JWKS_URI = 'https://login.eveonline.com/oauth/jwks';
const VALID_ISS = [
  'login.eveonline.com',
  'https://login.eveonline.com'
];

class SsoProvider {
  constructor(clientID) {
    this._clientID = clientID;
  }

  /**
   * @typedef {Object} Login
   * @property {string} url       - The URL your EVE login button should use
   * @property {string} state     - The state you must saved for the callback
   * @property {string} clearCode - The clearCode you must save for the callback
   */

  /**
   * Returns all the fields needed to start the authentication process.
   *
   * @param  {string} callbackUrl - the callback url set for your application
   *                                on developers.eveonline.com
   * @param  {array} scopes       - the scopes you are asking for on login
   * @return {Login}
   */
  getLogin(callbackUrl, scopes) {
    let clearCodeChallenge = this._buildClearCodeChallenge();
    let loginStateString = encode(WordArray.random(8).toString());

    return {
      url: this._getLoginUri(
          callbackUrl,
          scopes,
          loginStateString,
          clearCodeChallenge
      ),
      state: loginStateString,
      clearCode: clearCodeChallenge
    }
  }

  /**
   * @typedef {Object} ResultCallback
   * @property {string|null} accessToken
   * @property {string|null} refreshToken
   * @property {number|null} expiresIn
   * @property {array|null} scopes
   * @property {string|null} owner
   * @property {string|null} characterName
   * @property {string|null} characterID
   * @property {object} raw
   * @property {object} raw.token
   * @property {object} raw.jwt
   */

  /**
   * Returns the all the authentication information.
   *
   * @param {string} url            - The url of the current window, needed for
   *                                  extracting the query parameters.
   * @param {string} savedState     - state string saved previously
   * @param {string} savedClearCode - clear code saved previously
   * @return {ResultCallback}
   */
  async handleCallback(url, savedState, savedClearCode) {
    let params = this._extractParams(url);
    if (params === null) {
      throw new Error('No query parameters in the callback');
    }

    let { state, code } = params;
    if (savedState === null || savedState !== state) {
      throw new Error('Submitted and received state dont match');
    }

    let token = await this._fetchFirstToken(code, savedClearCode);

    let client = JwksRsa({
      jwksUri: JWKS_URI
    });

    let getKey = (header, callback) => {
      client.getSigningKey(header.kid, function(err, key) {
        let signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
      });
    }

    const readFilePromise = () => {
      return new Promise((resolve, reject) => {
        jwt.verify(
            token['access_token'],
            getKey,
            {},
            function(err, decoded) {
              if (err) {
                return reject(err);
              }

              resolve(decoded);
            }
        );
      })
    }

    let decodedJWT = await readFilePromise();

    if (!VALID_ISS.includes(decodedJWT['iss'])) {
      throw new Error('JWT returned an invalid iss');
    }

    return {
      accessToken: token.hasOwnProperty('access_token') ? token['access_token'] : null,
      refreshToken: token.hasOwnProperty('refresh_token') ? token['refresh_token'] : null,
      expiresIn: token.hasOwnProperty('expires_in') ? token['expires_in'] : null,
      scopes: decodedJWT.hasOwnProperty('scp') ? decodedJWT['scp'] : null,
      owner: decodedJWT.hasOwnProperty('owner') ? decodedJWT['owner'] : null,
      characterName: decodedJWT.hasOwnProperty('name') ? decodedJWT['name'] : null,
      characterID: decodedJWT.hasOwnProperty('sub') ? decodedJWT['sub'].replace('CHARACTER:EVE:', '') : null,
      raw: {
        token: token,
        jwt: decodedJWT
      }
    };
  }

  /**
   * @typedef {Object} ResultRefresh
   * @property {string|null} accessToken
   * @property {string|null} refreshToken
   * @property {number|null} expiresIn
   * @property {object} raw
   * @property {object} raw.token
   */

  /**
   * Returns a new access token from the given refresh token
   *
   * @param {string} refreshToken
   * @return {ResultRefresh}
   */
  async refresh(refreshToken) {
    let token = await this._fetchRefreshToken(refreshToken);

    return {
      accessToken: token.hasOwnProperty('access_token') ? token['access_token'] : null,
      refreshToken: token.hasOwnProperty('refresh_token') ? token['refresh_token'] : null,
      expiresIn: token.hasOwnProperty('expires_in') ? token['expires_in'] : null,
      raw: {
        token: token
      }
    }
  }

  /**
   * Return an object with 'code' and 'state' parameters, otherwise null.
   *
   * @returns {null|{code: string, state: string}}
   */
  _extractParams(url) {
    let { query } = new Url(url);
    if (query === '') {
      return null;
    }

    let params = new URLSearchParams(query);
    let codeParam = params.get('code');
    let stateParam = params.get('state');
    if (codeParam === null || stateParam === null) {
      return null;
    }

    return {
      code: codeParam,
      state: stateParam
    };
  }

  async _fetchFirstToken(code, codeVerifier) {
    let body = this._getFirstFetchFormData(code, codeVerifier);

    return this._fetchToken(body);
  }

  async _fetchRefreshToken(refreshToken) {
    let body = this._getRefreshFetchFormData(refreshToken);

    return this._fetchToken(body);
  }

  async _fetchToken(bodyToSend) {
    const url = TOKEN_URI;

    return await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'login.eveonline.com'
      },
      body: bodyToSend
    })
    .then(response => {
      if (response.ok) {
        return response.json();
      }

      /* To have access to the error message provided by the API we must first
         resolve the promise, simply throwing an error would prevent that. */

      return Promise.resolve(response.json())
      .then(responseInJson => {
        let errorMessageProperty = 'error_description';
        if (!responseInJson.hasOwnProperty(errorMessageProperty)) {
          throw Error(responseInJson);
        }

        return Promise.reject(responseInJson[errorMessageProperty]);
      });
    });
  }

  _getFirstFetchFormData(code, codeVerifier) {
    const params = new URLSearchParams({
      'grant_type': 'authorization_code',
      'code': code,
      'client_id': this._clientID,
      'code_verifier': codeVerifier,
    })

    return params.toString();
  }

  _getRefreshFetchFormData(refreshToken) {
    const params = new URLSearchParams({
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
      'client_id': this._clientID
    })

    return params.toString();
  }

  _buildQuery(params) {
    let query = '';
    for (let property in params) {
      if (!params.hasOwnProperty(property)) continue;

      if (query.length === 0) {
        query += '?';
      } else {
        query += '&';
      }

      query += property + '=';
      let propertyValue = params[property];
      if (Array.isArray(propertyValue)) {
        propertyValue.forEach(
            (element, index) => {
              if (index > 0) query += '%20';

              query += element;
            }
        );
      } else {
        query += propertyValue;
      }
    }

    return query;
  }

  _getLoginUri(callbackUrl, scopes, loginStateString, clearCodeChallenge) {
    let baseUri = LOGIN_URI;
    let uriParameters = {
      'response_type': 'code',
      'redirect_uri': callbackUrl,
      'client_id': this._clientID,
      'scope': scopes,
      'code_challenge': this._getEncodedCodeChallenge(clearCodeChallenge),
      'code_challenge_method': 'S256',
      'state': loginStateString,
    };

    // Using a custom function instead of 'url-search-params-polyfill' as
    // facebook broke the library messing with the native URLSearchParams.
    return baseUri + this._buildQuery(uriParameters);
  }

  _buildClearCodeChallenge() {
    let randomWord = WordArray.random(32);
    let encodedRandomWord = Base64.stringify(randomWord);
    return trim(encode(encodedRandomWord));
  }

  _getEncodedCodeChallenge(clearCodeChallenge) {
    let shaCodeChallenge = sha256(clearCodeChallenge);
    let base64sha = Base64.stringify(shaCodeChallenge);
    return trim(encode(base64sha));
  }
}

module.exports = SsoProvider;