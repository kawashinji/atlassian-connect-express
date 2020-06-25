const request = require("request");
const _ = require("lodash");
const moment = require("moment");
const jwt = require("atlassian-jwt");
const URI = require("urijs");
const RSVP = require("rsvp");
const querystring = require("querystring");
const OAuth2 = require("./oauth2");
const utils = require("./utils");

function HostClient(addon, context, clientKey) {
  utils.checkNotNull(addon, "addon");
  utils.checkNotNull(addon.settings, "addon.settings");
  this.addon = addon;
  this.context = context || {};
  this.clientKey = clientKey;
  this.oauth2 = new OAuth2(addon);

  return this;
}

HostClient.prototype.defaults = function(options) {
  return request.defaults.apply(null, this.modifyArgs(options));
};

HostClient.prototype.cookie = function() {
  return request.cookie.apply(null, arguments);
};

HostClient.prototype.jar = function() {
  return request.jar();
};

/**
 * Make a request to the host product as the specific user. Will request and retrieve an access token if necessary
 *
 * @param userKey - the key referencing the remote user to impersonate when making the request
 * @returns HostClient - `hostClient` object suitable for chaining
 */
HostClient.prototype.asUser = function(userKey) {
  if (!userKey) {
    throw new Error("A userKey must be provided to make a request as a user");
  }

  const product = this.addon.config.product();
  if (!product.isJIRA && !product.isConfluence) {
    throw new Error(
      "the asUser method is not available for " + product.id + " add-ons"
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
};

/**
 * Make a request to the host product as the specific user. Will request and retrieve and access token if necessary
 *
 * @param userAccountId - the Atlassian Account Id of the remote user to impersonate when making the request
 * @returns HostClient - `hostClient` object suitable for chaining.
 */
HostClient.prototype.asUserByAccountId = function(userAccountId) {
  if (!userAccountId) {
    throw new Error(
      "A userAccountId must be provided to make a request as a user"
    );
  }

  const product = this.addon.config.product();
  if (!product.isJIRA && !product.isConfluence) {
    throw new Error(
      "the asUserByAccountId method is not available for " +
        product.id +
        " add-ons"
    );
  }

  const impersonatingClient = new HostClient(
    this.addon,
    this.context,
    this.clientKey
  );
  impersonatingClient.userAccountId = userAccountId;
  return impersonatingClient;
};

HostClient.prototype.modifyArgs = function(
  options,
  augmentHeaders,
  callback,
  hostBaseUrl
) {
  const args = [];

  if (_.isString(options)) {
    options = { uri: options };
  }
  if (options.url) {
    options.uri = options.url;
    delete options.url;
  }
  if (options.form) {
    options.multipartFormData = options.form;
    delete options.form;
    this.addon.logger.warn(
      "options.form is deprecated: please use options.multipartFormData"
    );
  }
  if (options.urlEncodedFormData) {
    options.form = options.urlEncodedFormData;
    delete options.urlEncodedFormData;
  }

  let originalUri = options.uri;
  const targetUri = new URI(originalUri);
  const hostBaseUri = new URI(hostBaseUrl);

  if (options.qs) {
    targetUri.query(querystring.encode(options.qs));
    originalUri = targetUri.toString();
    delete options.qs;
  }

  if (!targetUri.origin()) {
    targetUri.origin(hostBaseUri.origin());
    const newPath = URI.joinPaths(hostBaseUri.path(), targetUri.path());
    targetUri.path(newPath.path());
  }

  options.uri = targetUri.toString();
  args.push(options);

  if (targetUri.origin() === hostBaseUri.origin()) {
    if (!options.headers) {
      options.headers = {};
    }

    if (augmentHeaders) {
      augmentHeaders(options.headers, originalUri);
    }

    options.jar = false;
  }

  if (callback) {
    args.push(callback);
  }

  return args;
};

HostClient.prototype.createJwtPayload = function(req) {
  const now = moment().utc(),
    jwtTokenValidityInMinutes = this.addon.config.jwt().validityInMinutes;

  const token = {
    iss: this.addon.key,
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
};

HostClient.prototype.getUserBearerToken = function(scopes, clientSettings) {
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
    return this.oauth2.getUserBearerTokenByUserAccountId(
      this.userAccountId,
      scopes,
      clientSettings
    );
  } else if (this.userKey) {
    return this.oauth2.getUserBearerToken(this.userKey, scopes, clientSettings);
  } else {
    throw new Error(
      "One of userAccountId or userKey must be provided. Did you call asUserByAccountId(userAccountId)?"
    );
  }
};

["get", "post", "put", "del", "head", "patch"].forEach(function(method) {
  // hostClient.get -> return function
  // hostClient.get(options, callback) -> get client settings -> augment options -> callback
  HostClient.prototype[method] = function(options, callback) {
    const self = this;

    return this.addon.settings
      .get("clientInfo", this.clientKey)
      .then(function(clientSettings) {
        if (!clientSettings) {
          const message =
            'There are no "clientInfo" settings in the store for tenant "' +
            self.clientKey +
            '"';
          self.addon.logger.warn(message);
          return RSVP.Promise.reject(message);
        }

        const clientContext = {
          clientSettings: clientSettings
        };
        if (self.userKey || self.userAccountId) {
          return self
            .getUserBearerToken([], clientSettings)
            .then(function(token) {
              clientContext.bearerToken = token.access_token;
              return RSVP.Promise.resolve(clientContext);
            });
        } else {
          return RSVP.Promise.resolve(clientContext);
        }
      })
      .then(
        function(clientContext) {
          const augmentHeaders = function(headers, relativeUri) {
            const uri = new URI(relativeUri);
            const query = uri.search(true);

            const httpMethod = method === "del" ? "delete" : method;

            if (!(self.userKey || self.userAccountId)) {
              const jwtPayload = self.createJwtPayload({
                  method: httpMethod,
                  path: uri.path(),
                  query: query
                }),
                jwtToken = jwt.encode(
                  jwtPayload,
                  clientContext.clientSettings.sharedSecret,
                  "HS256"
                );

              headers.authorization = "JWT " + jwtToken;
            } else {
              headers.authorization = "Bearer " + clientContext.bearerToken;
            }
            headers["User-Agent"] = self.addon.config.userAgent();
          };

          const args = self.modifyArgs(
            options,
            augmentHeaders,
            callback,
            clientContext.clientSettings.baseUrl
          );

          const multipartFormData = options.multipartFormData;
          delete options.multipartFormData;

          const _request = request[method].apply(null, args);

          if (multipartFormData) {
            const form = _request.form();

            _.forOwn(multipartFormData, function(value, key) {
              if (Array.isArray(value)) {
                form.append.apply(form, [key].concat(value));
              } else {
                form.append.apply(form, [key, value]);
              }
            });
          }

          return _request;
        },
        function(err) {
          callback(err);
        }
      );
  };
});

module.exports = HostClient;
