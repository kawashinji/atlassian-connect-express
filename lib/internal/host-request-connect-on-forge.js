const utils = require("./utils");
const fetch = require("node-fetch");
const request = require("request");
const _ = require("lodash");
const md5 = require("md5");
const moment = require("moment");

class HostClientConnectOnForge {
  constructor(addon, context, clientKey) {
    utils.checkNotNull(addon, "addon");
    utils.checkNotNull(addon.settings, "addon.settings");
    this.addon = addon;
    this.context = context || {};
    this.clientKey = clientKey;
  }

  /**
   * hash a data store index key for storing the access token in a cache
   *
   * @param {String} userIdentifier - The userIdentifier to create a cache key for
   * @param {Array} scopes - Access token scopes
   * @returns {String} A key which identifies the user's token in the data store
   */
  _hashedTokenCacheStoreKey(oauthClientId) {
    return `bearer:${md5(oauthClientId)}`; // personal information; Hash it.
  }

  /**
   * Looks up a cached bearer token for a given oauthClientId in the data store
   *
   * @param {String} oauthClientId
   * @param {String} clientKey
   * @returns {Promise} A promise that returns the access token if resolved, or an error if rejected
   */
  _getCachedBearerToken(oauthClientId, clientKey) {
    utils.checkNotNull(oauthClientId, "oauthClientId");
    utils.checkNotNull(clientKey, "clientSettings.clientKey");

    const key = this._hashedTokenCacheStoreKey(oauthClientId);
    return this.addon.settings.get(key, clientKey);
  }

  /**
   * Stores the bearer token in a cache
   *
   * @param {String} oauthClientId - oauthClientId
   * @param {String} bearerToken - bearerToken to be cached
   * @param {String} expiresAt - The time when the token expires
   * @param {String} clientSettings - Settings object for the current tenant
   * @returns {Promise} A promise that is resolved when the key is stored
   */
  _cacheBearerToken(oauthClientId, bearerToken, expiresAt, clientKey) {
    utils.checkNotNull(oauthClientId);
    utils.checkNotNull(clientKey);

    const key = this._hashedTokenCacheStoreKey(oauthClientId);
    const token = {
      token: bearerToken,
      expiresAt
    };

    return this.addon.settings.set(key, token, clientKey);
  }

  /**
   * Requesting the bearer token to token endpoint (auth0 proxy)
   *
   * @param {String} clientSettings - Settings object for the current tenant
   * @returns {Promise} A promise that returns the token object if resolved, or an error if rejected
   */
  async _getBearerToken(clientSettings) {
    utils.checkNotNull(clientSettings.baseUrl, "clientSettings.baseUrl");
    utils.checkNotNull(
      clientSettings.oauthClientId,
      "clientSettings.oauthClientId"
    );
    utils.checkNotNull(
      clientSettings.sharedSecret,
      "clientSettings.sharedSecret"
    );

    // TODO: Checking authType is oauth2 from clientSettings (once the hook is ready)

    let tokenEndpoint = "https://auth.atlassian.com/oauth/token";
    let identityAudience = "api.atlassian.com";
    if (utils.isJiraDevBaseUrl(clientSettings.baseUrl)) {
      tokenEndpoint = "https://auth.stg.atlassian.com/oauth/token";
      identityAudience = "api.stg.atlassian.com";
    }

    const payload = {
      grant_type: "client_credentials",
      client_id: clientSettings.oauthClientId,
      client_secret: clientSettings.sharedSecret,
      audience: identityAudience
    };

    try {
      const response = await fetch(tokenEndpoint, {
        method: "POST",
        body: JSON.stringify(payload),
        headers: {
          "Content-Type": "application/json"
        }
      });

      return await response.json();
    } catch (error) {
      throw new Error(
        `HTTP error while getting the bearer token from: ${error}`
      );
    }
  }

  /**
   * Requesting the bearer token condsidering the cache lifetime
   *
   * @param {String} clientSettings - Settings object for the current tenant
   * @returns {Promise} A promise that returns the token object if resolved, or an error if rejected
   */
  async getBearerToken(clientSettings) {
    try {
      const cachedToken = await this._getCachedBearerToken(
        clientSettings.oauthClientId,
        clientSettings.clientKey
      );

      if (cachedToken) {
        // cut the expiry time by a few seconds for leeway
        const tokenExpiryTime = moment
          .unix(cachedToken.expiresAt)
          .subtract(3, "seconds");
        const isTokenExpired = tokenExpiryTime.isBefore(moment());
        if (!isTokenExpired) {
          return cachedToken.token;
        }
      }

      // no available cache -> need to re-request a token from the server
      const now = moment();
      const token = await this._getBearerToken(clientSettings);

      // reset the cache
      const tokenExpiry = now.add(token.expires_in, "seconds").unix();
      await this._cacheBearerToken(
        clientSettings.oauthClientId,
        token,
        tokenExpiry,
        clientSettings.clientKey
      );
      return token;
    } catch (error) {
      throw new Error(`error while getting the bearer token: ${error}`);
    }
  }
}

["get", "post", "put", "del", "head", "patch"].forEach(method => {
  // HostClientConnectOnForge.get -> return function
  // HostClientConnectOnForge.get(options, callback) -> get client settings -> augment options -> callback
  HostClientConnectOnForge.prototype[method] = function (options, callback) {
    const self = this;

    return this.addon.settings
      .get("clientInfo", this.clientKey)
      .then(clientSettings => {
        if (!clientSettings) {
          const message = `There are no "clientInfo" settings in the store for tenant "${self.clientKey}"`;
          self.addon.logger.warn(message);
          return Promise.reject(message);
        }

        // TODO: remove this mock
        clientSettings.oauthClientId = "ObY6cFuS7zA2Nwq581rRMRRff6SYAmjY";
        clientSettings.sharedSecret =
          "2ONbondOFF1Wx2ANeh-G8vTbK905BeUJWv6DmmOOU1CEU-mdGdZjy0rLezhRnoQV";
        ///

        const clientContext = {
          clientSettings
        };

        return self.getBearerToken(clientSettings).then(token => {
          clientContext.bearerToken = token.access_token;
          return Promise.resolve(clientContext);
        });
      })
      .then(
        clientContext => {
          // TODO: convert request => node-fetch as request is `depreciated`. but make sure Formdata keeps working (i.e multipartFormData, urlEncodedFormData etc)
          const augmentHeaders = function (headers) {
            headers["User-Agent"] = self.addon.config.userAgent();
            headers.authorization = `Bearer ${clientContext.bearerToken}`;
          };

          // convert wrap [options.url] with the stargate url
          let stargateUrl = "https://api.atlassian.com";
          if (utils.isJiraDevBaseUrl(clientContext.clientSettings.baseUrl)) {
            stargateUrl = "https://api.stg.atlassian.com";
          }
          const requestUrl = options.url;
          let productType = clientContext.clientSettings.productType;
          let cloudId = clientContext.clientSettings.cloudId;

          // TODO: remove this mock and convert it into const
          // check for the confluence: productype is wiki ? or confluence ?
          productType = "jira";
          cloudId = "fddbd43d-75b6-4fb9-a004-c28db2706d70";
          ///

          options.url = utils.wrapUrlWithStargate(
            stargateUrl,
            requestUrl,
            productType,
            cloudId
          );

          const args = utils.modifyArgs(
            options,
            augmentHeaders,
            callback,
            stargateUrl
          );

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

module.exports = HostClientConnectOnForge;
