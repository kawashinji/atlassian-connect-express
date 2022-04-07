const utils = require("./utils");
const fetch = require("node-fetch");
const md5 = require("md5");
const moment = require("moment");

class ForgeOAuth2 {
  constructor(addon) {
    utils.checkNotNull(addon, "addon");
    utils.checkNotNull(addon.settings, "addon.settings");
    this.addon = addon;
  }

  /**
   * hash a data store index key for storing the access token in a cache
   *
   * @param {String} oauthClientId
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
    utils.checkNotUndefined(oauthClientId, "oauthClientId");
    utils.checkNotUndefined(clientKey, "clientSettings.clientKey");

    const key = this._hashedTokenCacheStoreKey(oauthClientId);
    return this.addon.settings.get(key, clientKey);
  }

  /**
   * Stores the bearer token in a cache
   *
   * @param {String} oauthClientId - oauthClientId
   * @param {String} bearerToken - bearerToken to be cached
   * @param {String} expiresAt - The time when the token expires
   * @param {String} clientKey
   * @returns {Promise} A promise that is resolved when the key is stored
   */
  _cacheBearerToken(oauthClientId, bearerToken, expiresAt, clientKey) {
    utils.checkNotUndefined(oauthClientId);
    utils.checkNotUndefined(clientKey);

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
   * @param {Object} clientSettings - Settings object for the current tenant
   * @returns {Promise} A promise that returns the token object if resolved, or an error if rejected
   */
  async _getBearerToken(clientSettings) {
    utils.checkNotUndefined(clientSettings.baseUrl, "clientSettings.baseUrl");
    utils.checkNotUndefined(
      clientSettings.oauthClientId,
      "clientSettings.oauthClientId"
    );
    utils.checkNotUndefined(
      clientSettings.sharedSecret,
      "clientSettings.sharedSecret"
    );

    const tokenEndpointProduction = "https://auth.atlassian.com/oauth/token";
    const identityAudienceProduction = "api.atlassian.com";

    const tokenEndpointStaging = "https://auth.stg.atlassian.com/oauth/token";
    const identityAudienceStaging = "api.stg.atlassian.com";

    const isJiraDev = utils.isJiraDevBaseUrl(clientSettings.baseUrl);
    const tokenEndpoint = isJiraDev
      ? tokenEndpointStaging
      : tokenEndpointProduction;
    const identityAudience = isJiraDev
      ? identityAudienceStaging
      : identityAudienceProduction;

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
   * @param {Object} clientSettings - Settings object for the current tenant
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

module.exports = ForgeOAuth2;
