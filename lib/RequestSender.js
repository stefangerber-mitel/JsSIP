const Logger = require('./Logger');
const JsSIP_C = require('./Constants');
const DigestAuthentication = require('./DigestAuthentication');
const Transactions = require('./Transactions');

const logger = new Logger('RequestSender');

// Default event handlers.
const EventHandlers = {
  onRequestTimeout  : () => {},
  onTransportError  : () => {},
  onReceiveResponse : () => {},
  onAuthenticated   : () => {}
};

module.exports = class RequestSender
{
  constructor(ua, request, eventHandlers)
  {
    this._ua = ua;
    this._eventHandlers = eventHandlers;
    this._method = request.method;
    this._request = request;
    this._auth = null;
    this._challenged = false;
    this._staled = false;

    // Define the undefined handlers.
    for (const handler in EventHandlers)
    {
      if (Object.prototype.hasOwnProperty.call(EventHandlers, handler))
      {
        if (!this._eventHandlers[handler])
        {
          this._eventHandlers[handler] = EventHandlers[handler];
        }
      }
    }

    // If ua is in closing process or even closed just allow sending Bye and ACK.
    if (ua.status === ua.C.STATUS_USER_CLOSED &&
        (this._method !== JsSIP_C.BYE || this._method !== JsSIP_C.ACK))
    {
      this._eventHandlers.onTransportError();
    }
  }

  /**
  * Create the client transaction and send the message.
  */
  send()
  {
    const eventHandlers = {
      onRequestTimeout  : () => { this._eventHandlers.onRequestTimeout(); },
      onTransportError  : () => { this._eventHandlers.onTransportError(); },
      onReceiveResponse : (response) => { this._receiveResponse(response); }
    };

    switch (this._method)
    {
      case 'INVITE':
        this.clientTransaction = new Transactions.InviteClientTransaction(
          this._ua, this._ua.transport, this._request, eventHandlers);
        break;
      case 'ACK':
        this.clientTransaction = new Transactions.AckClientTransaction(
          this._ua, this._ua.transport, this._request, eventHandlers);
        break;
      default:
        this.clientTransaction = new Transactions.NonInviteClientTransaction(
          this._ua, this._ua.transport, this._request, eventHandlers);
    }
    // If authorization JWT is present, use it.
    if (this._ua._configuration.authorization_jwt)
    {
      this._request.setHeader('Authorization', this._ua._configuration.authorization_jwt);
    }

    this.clientTransaction.send();
  }

  /**
  * Called from client transaction when receiving a correct response to the request.
  * Authenticate request if needed or pass the response back to the applicant.
  */
  _receiveResponse(response)
  {
    let challenge;
    let authorization_header_name;
    const status_code = response.status_code;

    /*
    * Authentication
    * Authenticate once. _challenged_ flag used to avoid infinite authentications.
    */
    if ((status_code === 401 || status_code === 407) &&
        (this._ua.configuration.password !== null || this._ua.configuration.ha1 !== null))
    {
      let authenticateType;

      if (response.status_code === 401)
      {
        authenticateType = 'www-authenticate';
        authorization_header_name = 'authorization';
      }
      else
      {
        authenticateType = 'proxy-authenticate';
        authorization_header_name = 'proxy-authorization';
      }

      const nrChallenges = response.getHeaders(authenticateType).length;

      // Verify it seems a valid challenge.
      if (nrChallenges === 0)
      {
        logger.debug(`${response.status_code} with wrong or missing challenge, cannot authenticate`);
        this._eventHandlers.onReceiveResponse(response);

        return;
      }

      // Construct a RegExp with which we can check if we received a challenge that
      // matches a supported digest algorithm
      let regexPattern = '';

      if (this._ua.configuration.supported_digest_algorithms &&
        this._ua.configuration.supported_digest_algorithms.length)
      {
        // Traverse through the configuration.supported_digest_algorithms array (which contains
        // values from DIGEST_ALGORITHMS) and construct a regex pattern from the values.
        this._ua.configuration.supported_digest_algorithms.
          forEach((algorithm, idx, array) =>
          {
            regexPattern += `^${algorithm}$${idx < (array.length - 1) ? '|' : ''}`;
          });
      }
      else
      {
        // By default, all algorithms from DIGEST_ALGORITHMS are supported
        regexPattern = `^${JsSIP_C.DIGEST_ALGORITHMS.MD5}$|^${JsSIP_C.DIGEST_ALGORITHMS.MD5_SESS}$|^${JsSIP_C.DIGEST_ALGORITHMS.SHA_256}$|^${JsSIP_C.DIGEST_ALGORITHMS.SHA_256_SESS}$|^${JsSIP_C.DIGEST_ALGORITHMS.SHA_512_256}$|^${JsSIP_C.DIGEST_ALGORITHMS.SHA_512_256_SESS}$`;
      }

      logger.debug(`RequestSender._receiveResponse - regexPattern = ${regexPattern}`);

      const digestAlgorithmsRegEx = new RegExp(regexPattern);

      // If there are multiple challenges in the response then we have to pick the
      // first one with a supported algorithm while skipping those with unsupported algorithms.
      for (let i = 0; i < nrChallenges; i++)
      {
        const challengeCandidate = response.parseHeader(authenticateType, i);

        // According to RFC 8760, section 2.4, "The client MUST ignore any challenge it
        // does not understand." A parsing error might be interpreted that way.
        if (!challengeCandidate)
        {
          continue;
        }

        // Test if the challenge contains a supported digest algorithm. If it doesn't define
        // an algorithm at all then this means it defaults to MD5.
        if (digestAlgorithmsRegEx.test(challengeCandidate.algorithm ?
          challengeCandidate.algorithm : JsSIP_C.DIGEST_ALGORITHMS.MD5))
        {
          challenge = challengeCandidate;
          break;
        }
      }

      // Verify it seems a valid challenge.
      if (!challenge)
      {
        logger.debug(`${response.status_code} with wrong or missing challenge, cannot authenticate`);
        this._eventHandlers.onReceiveResponse(response);

        return;
      }

      if (!this._challenged || (!this._staled && challenge.stale === true))
      {
        if (!this._auth)
        {
          this._auth = new DigestAuthentication({
            username        : this._ua.configuration.authorization_user,
            password        : this._ua.configuration.password,
            realm           : this._ua.configuration.realm,
            ha1             : this._ua.configuration.ha1,
            digestAlgorithm : this._ua.lastUsedDigestAlgorithm
          });
        }

        // Verify that the challenge is really valid.
        if (!this._auth.authenticate(this._request, challenge))
        {
          this._eventHandlers.onReceiveResponse(response);

          return;
        }
        this._challenged = true;

        // Update ha1 and realm in the UA.
        this._ua.set('realm', this._auth.get('realm'));
        this._ua.set('ha1', this._auth.get('ha1'));
        // Update used digest algorithm in the UA.
        this._ua.lastUsedDigestAlgorithm = this._auth.get('algorithm');

        if (challenge.stale)
        {
          this._staled = true;
        }

        this._request = this._request.clone();
        this._request.cseq += 1;
        this._request.setHeader('cseq', `${this._request.cseq} ${this._method}`);
        this._request.setHeader(authorization_header_name, this._auth.toString());

        this._eventHandlers.onAuthenticated(this._request);
        this.send();
      }
      else
      {
        this._eventHandlers.onReceiveResponse(response);
      }
    }
    else
    {
      this._eventHandlers.onReceiveResponse(response);
    }
  }
};
