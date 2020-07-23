# eve-oauth2-client

This client-side module is able to handle the authentication process for the oAuth2 EVE Online login system, without the need of a backend.

---

## Install
Register your application to https://developers.eveonline.com/ specifying the callback url of your application, and the scopes you'll ask for.   
The page will provide you a "client ID" that will be needed for handling the authentication.

To install the module: 
 ```
npm install --save eve-oauth2-client
```

## Usage
Import the package:
```javascript
import SsoProvider from 'eve-oauth2-client';
```

### Login
The first step is creating the login button with the url that will allow to start the authentication process:
```javascript
// Client ID of your application on developers.eveonline.com
let sso = new SsoProvider(clientID);

// The scopes needed by your application,
// for a complete list visit esi.evetech.net
let scopes = [
  'esi-location.read_location.v1',
  'esi-location.read_ship_type.v1',
  'esi-location.read_online.v1'
];

// url       - what your login button will link to.
// state     - a parameter you'll need to save and will be needed
//             when handling the callback.
// clearCode - another paramter to save needed for the callback.
let { url, state, clearCode } = sso.getLogin(callbackUrl, scopes);

// as an example, we can store the state and clearCode on localstorage
window.localStorage.setItem('state', state);
window.localStorage.setItem('clearCode', clearCode);
```

### Callback
On your callback page you'll need to call the asyncronous `handleCallback` method of the sso instance, providing the current window url, and the previously saved state and clear code.
```javascript
let sso = new SsoProvider(clientID);
let windowUrl = window.location.href;

// using localstorage as the previous example
let state = window.localStorage.getItem('state');
let clearCode = window.localStorage.getItem('clearCode');

let result = sso.handleCallback(windowUrl, state, clearCode);
```
If the authentication succeeded, the `handleCallback` method should return an object with the following properties:
- accessToken
- refreshToken
- expiresIn - seconds left before the accessToken expiration
- scopes - the array of previously requested scopes
- owner
- characterName
- characterID
- raw.token - the raw access token json received
- raw.jwt - the raw decoded jwt json received
```javascript
result
    .then(data => console.log(data.characterName))
    .catch(e => console.error(e));

// -> My Awesome Character Name
```

### Refresh
When the access token will need to be refreshed, you can call the `refresh` method of the sso instance, providing the previous refresh token, the return object should have those properties:
- accessToken
- refreshToken
- expiresIn
- raw.token - the raw token json object
```javascript
let sso = new SsoProvider(clientID);

sso.refresh(previouslySavedRefreshToken)
    .then(data => console.log(data.expiresIn))
    .catch(e => console.error(e));

// -> 1200
```