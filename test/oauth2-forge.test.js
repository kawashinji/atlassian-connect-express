const OAuth2 = require("../lib/internal/oauth2-forge");
const mocks = require("./mocks");
const moment = require("moment");
const _ = require("lodash");

describe("OAuth2 for Forge app through oauth0 proxy (https://auth.atlassian.com)", () => {
  const clientSettings = {
    clientKey: "test-client-key",
    sharedSecret: "shared-secret",
    baseUrl: "https://test.atlassian.net",
    oauthClientId: "oauth-client-id"
  };

  const mockAddon = function () {
    return {
      key: "test-addon-key",
      descriptor: {
        scopes: ["READ", "WRITE"]
      },
      logger: require("./logger"),
      settings: mocks.store(clientSettings, clientSettings.clientKey)
    };
  };

  describe("#getBearerToken", () => {
    it("calls OAuth service", async () => {
      const authServiceMock = mocks.oauth2Forge.service();

      const addon = mockAddon();
      const token = await new OAuth2(addon).getBearerToken(clientSettings);
      authServiceMock.done();
      expect(token).not.toBeUndefined();
    });

    it("calls staging OAuth service for jira-dev instances", async () => {
      const authServiceMock = mocks.oauth2Forge.service(
        null,
        "https://auth.stg.atlassian.com"
      );
      const addon = mockAddon();

      const settings = _.extend({}, clientSettings, {
        baseUrl: "https://test.jira-dev.com"
      });
      const token = await new OAuth2(addon).getBearerToken(settings);
      authServiceMock.done();
      expect(token).not.toBeUndefined();
    });

    it("stores token in cache", async () => {
      const authServiceMock = mocks.oauth2Forge.service();

      const addon = mockAddon();
      const oauth2 = new OAuth2(addon);
      await oauth2.getBearerToken(clientSettings);
      authServiceMock.done();

      const cacheKey = oauth2._hashedTokenCacheStoreKey(
        clientSettings.oauthClientId
      );
      const cachedToken = await addon.settings.get(
        cacheKey,
        clientSettings.clientKey
      );
      expect(cachedToken.token).toEqual(mocks.oauth2Forge.ACCESS_TOKEN);
    });

    it("retrieves token from cache", async () => {
      const authServiceMock = mocks.oauth2Forge.service();

      const addon = mockAddon();
      const oauth2 = new OAuth2(addon);

      const cachedToken = {
        expiresAt: moment().add(5, "minutes").unix(),
        token: {
          access_token: "cached",
          expires_in: 500,
          token_type: "Bearless"
        }
      };

      const cacheKey = oauth2._hashedTokenCacheStoreKey(
        clientSettings.oauthClientId
      );
      await addon.settings.set(cacheKey, cachedToken, clientSettings.clientKey);
      const token = await new OAuth2(addon).getBearerToken(clientSettings);

      // should not have called out to external service
      expect(authServiceMock.isDone()).toBe(false);
      expect(token).toEqual(cachedToken.token);
    });

    it("bypasses token cache if expired", async () => {
      mocks.oauth2Forge.service();

      const addon = mockAddon();
      const oauth2 = new OAuth2(addon);

      const cachedToken = {
        expiresAt: moment().subtract(5, "minutes").unix(),
        token: {
          access_token: "cached",
          expires_in: 500,
          token_type: "Bearless"
        }
      };

      const cacheKey = oauth2._hashedTokenCacheStoreKey(
        clientSettings.oauthClientId
      );
      await addon.settings.set(cacheKey, cachedToken, clientSettings.clientKey);
      const token = await new OAuth2(addon).getBearerToken(clientSettings);

      expect(token).toEqual(mocks.oauth2Forge.ACCESS_TOKEN);
    });
  });
});
