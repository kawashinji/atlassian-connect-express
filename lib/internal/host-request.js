const request = require("request");
const _ = require("lodash");
const moment = require("moment");
const jwt = require("atlassian-jwt");
const URI = require("urijs");
const ConnectImporsonation = require("./oauth2");
const OAuth2Identity = require("./oauth2-identity");
const utils = require("./utils");

class HostClient {
  constructor(addon, context, clientKey) {
    utils.checkNotNull(addon, "addon");
    utils.checkNotNull(addon.settings, "addon.settings");
    this.addon = addon;
    this.context = context || {};
    this.clientKey = clientKey;
    this.connectImporsonation = new ConnectImporsonation(addon);
    this.oauth2 = new OAuth2Identity(addon);
    this.usingOAuth2Flag = false;
  }

  defaults(options) {
    return request.defaults.apply(null, this.modifyArgs(options));
  }

  cookie() {
    return request.cookie.apply(null, arguments);
  }

  jar() {
    return request.jar();
  }

  /**
   * Make a request to the host product as the specific user. Will request and retrieve an access token if necessary
   *
   * @param userKey - the key referencing the remote user to impersonate when making the request
   * @returns HostClient - `hostClient` object suitable for chaining
   */
  asUser(userKey) {
    if (!userKey) {
      throw new Error("A userKey must be provided to make a request as a user");
    }

    const product = this.addon.config.product();
    if (!product.isJIRA && !product.isConfluence) {
      throw new Error(
        `the asUser method is not available for ${product.id} add-ons`
      );
    }

    // Warn that this is deprecated
    console.warn(
      "This has been deprecated, as per https://ecosystem.atlassian.net/browse/ACEJS-115"
    );

    const impersonatingClient = new HostClient(
      this.addon,
      this.context,
      this.clientKey
    );
    impersonatingClient.userKey = userKey;
    return impersonatingClient;
  }

  /**
   * Make a request to the host product as the specific user. Will request and retrieve and access token if necessary
   *
   * @param userAccountId - the Atlassian Account Id of the remote user to impersonate when making the request
   * @returns HostClient - `hostClient` object suitable for chaining.
   */
  asUserByAccountId(userAccountId) {
    if (!userAccountId) {
      throw new Error(
        "A userAccountId must be provided to make a request as a user"
      );
    }

    const product = this.addon.config.product();
    if (!product.isJIRA && !product.isConfluence) {
      throw new Error(
        `the asUserByAccountId method is not available for ${product.id} add-ons`
      );
    }

    const impersonatingClient = new HostClient(
      this.addon,
      this.context,
      this.clientKey
    );
    impersonatingClient.userAccountId = userAccountId;
    return impersonatingClient;
  }

  modifyArgs(options, augmentHeaders, callback, clientSettings) {
    if (this.usingOAuth2Flag) {
      // convert wrap [options.url] with the stargate url
      let stargateUrl = "https://api.atlassian.com";
      if (utils.isJiraDevBaseUrl(clientSettings.baseUrl)) {
        stargateUrl = "https://api.stg.atlassian.com";
      }
      const requestUrl = options.url;
      const productType = clientSettings.productType; // TODO: check for the confluence: productype is wiki ? or confluence ?
      const cloudId = clientSettings.cloudId;

      options.url = utils.wrapUrlWithStargate(
        stargateUrl,
        requestUrl,
        productType,
        cloudId
      );

      return utils.modifyArgs(options, augmentHeaders, callback, stargateUrl);
    }

    return utils.modifyArgs(
      options,
      augmentHeaders,
      callback,
      clientSettings.baseUrl
    );
  }

  createJwtPayload(req, iss = this.addon.key) {
    const now = moment().utc(),
      jwtTokenValidityInMinutes = this.addon.config.jwt().validityInMinutes;

    const token = {
      iss,
      iat: now.unix(),
      exp: now.add(jwtTokenValidityInMinutes, "minutes").unix(),
      qsh: jwt.createQueryStringHash(jwt.fromExpressRequest(req))
    };

    if (this.addon.config.product().isBitbucket) {
      token.sub = this.clientKey;
    } else if (
      this.addon.config.product().isJIRA ||
      this.addon.config.product().isConfluence
    ) {
      token.aud = [this.clientKey];
    }

    return token;
  }

  getUserBearerToken(scopes, clientSettings) {
    utils.checkNotNull(clientSettings.baseUrl, "clientSettings.baseUrl");
    utils.checkNotNull(
      clientSettings.oauthClientId,
      "clientSettings.oauthClientId"
    );
    utils.checkNotNull(
      clientSettings.sharedSecret,
      "clientSettings.sharedSecret"
    );

    if (this.userAccountId) {
      return this.connectImporsonation.getUserBearerTokenByUserAccountId(
        this.userAccountId,
        scopes,
        clientSettings
      );
    } else if (this.userKey) {
      return this.connectImporsonation.getUserBearerToken(
        this.userKey,
        scopes,
        clientSettings
      );
    } else {
      throw new Error(
        "One of userAccountId or userKey must be provided. Did you call asUserByAccountId(userAccountId)?"
      );
    }
  }

  getBearerToken(clientSettings) {
    if (this.usingOAuth2Flag) {
      return this.oauth2.getBearerToken(clientSettings);
    }

    throw new Error("usingOAuth2Flag is OFF. Did you call usingOAuth2()?");
  }

  /**
   * Tagging to be not using bearer token
   *
   * @returns HostClient - `HostClient` object suitable for chaining
   */
  usingJwt() {
    const client = new HostClient(this.addon, this.context, this.clientKey);
    client.usingOAuth2Flag = false;
    delete client.userKey;
    delete client.userAccountId;
    return client;
  }

  /**
   * Tagging usingOAuth2Flag (but this is the oauth2 through the auth0 proxy, nothing to do with the connect imporsonation)
   *
   * @returns HostClient - `HostClient` object suitable for chaining
   */
  usingOAuth2() {
    const product = this.addon.config.product();
    if (!product.isJIRA && !product.isConfluence) {
      throw new Error(
        `the usingOAuth2 method is not available for ${product.id} add-ons`
      );
    }

    const client = new HostClient(this.addon, this.context, this.clientKey);
    client.usingOAuth2Flag = true;
    delete client.userKey;
    delete client.userAccountId;
    return client;
  }
}

["get", "post", "put", "del", "head", "patch"].forEach(method => {
  // hostClient.get -> return function
  // hostClient.get(options, callback) -> get client settings -> augment options -> callback
  HostClient.prototype[method] = function (options, callback) {
    const self = this;

    return this.addon.settings
      .get("clientInfo", this.clientKey)
      .then(clientSettings => {
        if (!clientSettings) {
          const message = `There are no "clientInfo" settings in the store for tenant "${self.clientKey}"`;
          self.addon.logger.warn(message);
          return Promise.reject(message);
        }

        const clientContext = {
          clientSettings
        };
        const usingConnectImporsonation = self.userKey || self.userAccountId;
        if (usingConnectImporsonation) {
          return self.getUserBearerToken([], clientSettings).then(token => {
            clientContext.bearerToken = token.access_token;
            return Promise.resolve(clientContext);
          });
        } else if (self.usingOAuth2Flag) {
          return self.getBearerToken(clientSettings).then(token => {
            clientContext.bearerToken = token.access_token;
            return Promise.resolve(clientContext);
          });
        } else {
          return Promise.resolve(clientContext);
        }
      })
      .then(
        clientContext => {
          const augmentHeaders = function (headers, relativeUri) {
            const uri = new URI(relativeUri);
            const query = uri.search(true);

            const httpMethod = method === "del" ? "delete" : method;
            headers["User-Agent"] = self.addon.config.userAgent();

            // don't authenticate the request, which can be useful for running operations
            // as an "anonymous user" such as evaluating permissions
            if (options.anonymous) {
              return;
            }

            if (!clientContext.bearerToken) {
              const jwtPayload = self.createJwtPayload(
                  {
                    method: httpMethod,
                    path: uri.path(),
                    query
                  },
                  clientContext.clientSettings.key
                ),
                jwtToken = jwt.encodeSymmetric(
                  jwtPayload,
                  clientContext.clientSettings.sharedSecret,
                  "HS256"
                );

              headers.authorization = `JWT ${jwtToken}`;
            } else {
              headers.authorization = `Bearer ${clientContext.bearerToken}`;
            }
          };

          const args = self.modifyArgs(
            options,
            augmentHeaders,
            callback,
            clientContext.clientSettings
          );

          /* TODO: convert request => node-fetch as request is `depreciated`. But please consider these in conversion
          1) make sure Formdata keeps working as expected (i.e multipartFormData, urlEncodedFormData etc)
          2) consider how the current app developers are using callback in the app server. (i.e the `request` module is using function(err, response, body) formatted callback)
          */
          const multipartFormData = options.multipartFormData;
          delete options.multipartFormData;

          const _request = request[method].apply(null, args);

          if (multipartFormData) {
            const form = _request.form();

            _.forOwn(multipartFormData, (value, key) => {
              if (Array.isArray(value)) {
                form.append.apply(form, [key].concat(value));
              } else {
                form.append.apply(form, [key, value]);
              }
            });
          }

          return _request;
        },
        err => {
          self.addon.logger.error(err);
          callback(err);
        }
      );
  };
});

module.exports = HostClient;
