const Logger = require('./Logger');
const Utils = require('./Utils');

const logger = new Logger('DigestAuthentication');

module.exports = class DigestAuthentication
{
  constructor(credentials)
  {
    this._credentials = credentials;
    this._cnonce = null;
    this._nc = 0;
    this._ncHex = '00000000';
    this._algorithm = null;
    this._realm = null;
    this._nonce = null;
    this._opaque = null;
    this._stale = null;
    this._qop = null;
    this._method = null;
    this._uri = null;
    this._ha1 = null;
    this._response = null;
    this._userhash = null;
    this._charset = null;
  }

  get(parameter)
  {
    switch (parameter)
    {
      case 'realm':
        return this._realm;

      case 'ha1':
        return this._ha1;

      default:
        logger.warn('get() | cannot get "%s" parameter', parameter);

        return undefined;
    }
  }

  /**
  * Performs Digest authentication given a SIP request and the challenge
  * received in a response to that request.
  * Returns true if auth was successfully generated, false otherwise.
  */
  authenticate({ method, ruri, body }, challenge, cnonce = null /* test interface */)
  {
    this._algorithm = challenge.algorithm;
    this._realm = challenge.realm;
    this._nonce = challenge.nonce;
    this._opaque = challenge.opaque;
    this._stale = challenge.stale;
    this._userhash = challenge.userhash;
    this._charset = challenge.charset;

    if (this._algorithm)
    {
      if (!/^MD5$|^MD5-SESS$|^SHA-256$|^SHA-256-SESS$|^SHA-512-256$|^SHA-512-256-SESS$/.test(this._algorithm))
      {
        logger.warn(`authenticate() | challenge with unsupported Digest algorithm ${this._algorithm}, authentication aborted`);

        return false;
      }
    }
    else
    {
      this._algorithm = 'MD5';
    }

    if (!this._nonce)
    {
      logger.warn('authenticate() | challenge without Digest nonce, authentication aborted');

      return false;
    }

    if (!this._realm)
    {
      logger.warn('authenticate() | challenge without Digest realm, authentication aborted');

      return false;
    }

    // If the challenge contains the optional charset parameter then it must
    // be UTF-8 according to RFC 7616, section 3.3
    if (this._charset && this._charset !== 'UTF-8')
    {
      logger.warn(`authenticate() | challenge with unsupported Digest charset ${this._charset}, authentication aborted`);

      return false;
    }

    // If no plain SIP password is provided.
    if (!this._credentials.password)
    {
      // If ha1 is not provided we cannot authenticate.
      if (!this._credentials.ha1)
      {
        logger.warn('authenticate() | no plain SIP password nor ha1 provided, authentication aborted');

        return false;
      }

      // If the realm does not match the stored realm we cannot authenticate.
      if (this._credentials.realm !== this._realm)
      {
        logger.warn('authenticate() | no plain SIP password, and stored `realm` does not match the given `realm`, cannot authenticate [stored:"%s", given:"%s"]', this._credentials.realm, this._realm);

        return false;
      }
    }

    // 'qop' can contain a list of values (Array). Let's choose just one.
    if (challenge.qop)
    {
      if (challenge.qop.indexOf('auth-int') > -1)
      {
        this._qop = 'auth-int';
      }
      else if (challenge.qop.indexOf('auth') > -1)
      {
        this._qop = 'auth';
      }
      else
      {
        // Otherwise 'qop' is present but does not contain 'auth' or 'auth-int', so abort here.
        logger.warn('authenticate() | challenge without Digest qop different than "auth" or "auth-int", authentication aborted');

        return false;
      }
    }
    else
    {
      this._qop = null;
    }

    // Fill other attributes.

    this._method = method;
    this._uri = ruri;
    this._cnonce = cnonce || Utils.createRandomToken(12);
    this._nc += 1;
    const hex = Number(this._nc).toString(16);

    this._ncHex = '00000000'.substr(0, 8-hex.length) + hex;

    // Nc-value = 8LHEX. Max value = 'FFFFFFFF'.
    if (this._nc === 4294967296)
    {
      this._nc = 1;
      this._ncHex = '00000001';
    }

    // Calculate the Digest "response" value.

    // If we have plain SIP password then regenerate ha1.
    if (this._credentials.password)
    {
      if (this._algorithm.endsWith('-SESS'))
      {
        // HA1 = HASH(A1) = HASH(HASH(username:realm:password):nonce:cnonce).
        const hurp = this._calcHash(`${this._credentials.username}:${this._realm}:${this._credentials.password}`);

        this._ha1 = this._calcHash(`${hurp}:${this._nonce}:${this._cnonce}`);
      }
      else
      {
        // HA1 = HASH(A1) = HASH(username:realm:password).
        this._ha1 = this._calcHash(`${this._credentials.username}:${this._realm}:${this._credentials.password}`);
      }
    }
    // Otherwise reuse the stored ha1.
    else
    {
      this._ha1 = this._credentials.ha1;
    }

    let a2;
    let ha2;

    if (this._qop === 'auth')
    {
      // HA2 = HASH(A2) = HASH(method:digestURI).
      a2 = `${this._method}:${this._uri}`;
      ha2 = this._calcHash(a2);

      logger.debug('authenticate() | using qop=auth [a2:"%s"]', a2);

      // Response = HASH(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
      this._response = this._calcHash(`${this._ha1}:${this._nonce}:${this._ncHex}:${this._cnonce}:auth:${ha2}`);

    }
    else if (this._qop === 'auth-int')
    {
      // HA2 = HASH(A2) = HASH(method:digestURI:HASH(entityBody)).
      a2 = `${this._method}:${this._uri}:${this._calcHash(body ? body : '')}`;
      ha2 = this._calcHash(a2);

      logger.debug('authenticate() | using qop=auth-int [a2:"%s"]', a2);

      // Response = HASH(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
      this._response = this._calcHash(`${this._ha1}:${this._nonce}:${this._ncHex}:${this._cnonce}:auth-int:${ha2}`);

    }
    else if (this._qop === null)
    {
      // HA2 = HASH(A2) = HASH(method:digestURI).
      a2 = `${this._method}:${this._uri}`;
      ha2 = this._calcHash(a2);

      logger.debug('authenticate() | using qop=null [a2:"%s"]', a2);

      // Response = HASH(HA1:nonce:HA2).
      this._response = this._calcHash(`${this._ha1}:${this._nonce}:${ha2}`);
    }

    logger.debug('authenticate() | response generated');

    return true;
  }

  /**
  * Return the Proxy-Authorization or WWW-Authorization header value.
  */
  toString()
  {
    const auth_params = [];

    if (!this._response)
    {
      throw new Error('response field does not exist, cannot generate Authorization header');
    }

    auth_params.push(`algorithm=${this._algorithm}`);

    if (this._userhash !== undefined)
    {
      const username = this._userhash ? this._calcHash(`${this._credentials.username}:${this._realm}`) :
        this._credentials.username;

      auth_params.push(`username="${username}"`);
      auth_params.push(`userhash=${this._userhash}`);
    }
    else
    {
      auth_params.push(`username="${this._credentials.username}"`);
    }

    auth_params.push(`realm="${this._realm}"`);
    auth_params.push(`nonce="${this._nonce}"`);
    auth_params.push(`uri="${this._uri}"`);
    auth_params.push(`response="${this._response}"`);
    if (this._opaque)
    {
      auth_params.push(`opaque="${this._opaque}"`);
    }
    if (this._qop)
    {
      auth_params.push(`qop=${this._qop}`);
      auth_params.push(`cnonce="${this._cnonce}"`);
      auth_params.push(`nc=${this._ncHex}`);
    }

    return `Digest ${auth_params.join(', ')}`;
  }

  _calcHash(str)
  {
    let retVal;

    switch (this._algorithm)
    {
      case 'MD5':
      case 'MD5-SESS':
        retVal = Utils.calculateMD5(str);
        break;

      case 'SHA-256':
      case 'SHA-256-SESS':
        retVal = Utils.calculateSHA256(str);
        break;

      case 'SHA-512-256':
      case 'SHA-512-256-SESS':
        retVal = Utils.calculateSHA512_256(str);
        break;

      default:
        retVal = Utils.calculateMD5(str);
        break;
    }

    return retVal;
  }
};
