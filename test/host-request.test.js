const jwt = require("atlassian-jwt");
const nock = require("nock");
const extend = require("extend");
const _ = require("lodash");
const helper = require("./test_helper");
const mocks = require("./mocks");
const config = require("../lib/internal/config");
const HostRequest = require("../lib/internal/host-request");

const TEST_REQUEST_URL = "/some/path/on/host";

describe("Host Request", () => {
  const clientSettings = {
    clientKey: "test-client-key",
    oauthClientId: "oauth-client-id",
    sharedSecret: "shared-secret",
    baseUrl: "https://test.atlassian.net",
    key: "client-settings-key",
    productType: "jira"
  };

  const createAddonConfig = function (opts) {
    opts = extend(
      {
        jwt: {
          validityInMinutes: 3
        }
      },
      opts
    );

    return config({}, "development", {
      development: opts
    });
  };

  const mockAddon = function (addonConfig) {
    if (!addonConfig) {
      addonConfig = {};
    }

    let addonStore = mocks.store(clientSettings, clientSettings.clientKey);
    if (addonConfig.clientSettingsOverride) {
      const settings = addonConfig.clientSettingsOverride;
      addonStore = mocks.store(settings, settings.clientKey);
    }

    return {
      logger: require("./logger"),
      key: "test-addon-key",
      config: createAddonConfig(addonConfig),
      descriptor: {
        scopes: ["READ", "WRITE"]
      },
      settings: addonStore
    };
  };

  function getHttpClient(addonConfig, context) {
    if (arguments.length === 0) {
      addonConfig = context = {};
    } else if (arguments.length === 1) {
      context = addonConfig;
      addonConfig = {};
    }

    const a = mockAddon(addonConfig);
    return new HostRequest(a, context, clientSettings.clientKey);
  }

  function interceptRequest(
    testCallback,
    replyCallback,
    options,
    errorCallback
  ) {
    const opts = extend(
      {
        baseUrl: clientSettings.baseUrl,
        method: "get",
        path: TEST_REQUEST_URL,
        httpClientContext: {}
      },
      options || {}
    );

    if (!opts.requestPath) {
      opts.requestPath = opts.path;
    }
    if (!opts.uri) {
      opts.uri = opts.requestPath;
    }

    let interceptor = nock(opts.baseUrl)[opts.method](opts.path);
    if (opts.overrideMockBaseUrl) {
      interceptor = nock(opts.overrideMockBaseUrl)[opts.method](opts.path);
    }

    if (opts.qs) {
      interceptor = interceptor.query(opts.qs);
    }
    interceptor = interceptor.reply(replyCallback);

    let httpClient = getHttpClient(
      opts.addonConfig,
      opts.httpClientContext,
      opts.clientSettingsOverride
    );

    if (opts.httpClientWrapper) {
      httpClient = opts.httpClientWrapper(httpClient);
    }

    const httpClientOpts = _.cloneDeep(opts);
    delete httpClientOpts.baseUrl;
    delete httpClientOpts.method;
    delete httpClientOpts.path;
    delete httpClientOpts.requestPath;
    delete httpClientOpts.httpClientContext;

    httpClient[opts.method](httpClientOpts, err => {
      if (interceptor.isDone()) {
        testCallback();
      } else {
        errorCallback(err);
      }
    });
  }

  function interceptRequestAsUser(testCallback, replyCallback, options) {
    const userKey = options.userKey;
    delete options.userKey;
    const opts = extend({}, options, {
      httpClientWrapper(httpClient) {
        return httpClient.asUser(userKey);
      }
    });
    interceptRequest(testCallback, replyCallback, opts);
  }

  function interceptRequestAsUserByAccountId(
    testCallback,
    replyCallback,
    options
  ) {
    const userAccountId = options.userAccountId;
    delete options.userAccountId;
    const opts = extend({}, options, {
      httpClientWrapper(httpClient) {
        return httpClient.asUserByAccountId(userAccountId);
      }
    });
    interceptRequest(testCallback, replyCallback, opts);
  }

  function interceptRequestUsingJwt(testCallback, replyCallback, options) {
    const opts = extend({}, options, {
      httpClientWrapper(httpClient) {
        return httpClient.usingJwt();
      }
    });
    interceptRequest(testCallback, replyCallback, opts);
  }

  function interceptRequestWithClientCredentialsGrant(
    testCallback,
    replyCallback,
    errorCallback,
    options
  ) {
    const mockBaseUrl = options.apiGatewayUrl
      ? `${options.apiGatewayUrl}/ex/${clientSettings.productType}/${options.addonConfig.clientSettingsOverride.cloudId}`
      : undefined;
    const opts = extend({}, options, {
      httpClientWrapper(httpClient) {
        return httpClient.clientCredentialsGrant();
      },
      overrideMockBaseUrl: mockBaseUrl
    });
    interceptRequest(testCallback, replyCallback, opts, errorCallback);
  }

  function mockApiGatewayRequest(clientSettingsOverride) {
    const apiGatewayBaseUrl = "https://api.atlassian.com";
    const requestBaseUrl = `${apiGatewayBaseUrl}/ex/${clientSettingsOverride.productType}/${clientSettingsOverride.cloudId}`;
    nock(requestBaseUrl).post(TEST_REQUEST_URL).reply(200);
    nock(requestBaseUrl).get(TEST_REQUEST_URL).reply(200);
    mocks.oauth2Forge.service();
  }

  it("constructs non-null get request", () => {
    return new Promise(done => {
      interceptRequest(done, 200);
    });
  });

  describe("Headers", () => {
    it("get request has headers", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(done, function (uri, requestBody) {
          expect(this.req.headers).toBeDefined();
        });
      });
    });

    it("get request has user-agent header", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(done, function (uri, requestBody) {
          expect(
            this.req.headers["user-agent"].startsWith(
              "atlassian-connect-express/"
            )
          ).toBe(true);
        });
      });
    });

    it("get request has user-agent version set to package version", () => {
      return new Promise(done => {
        const aceVersion = require("../package.json").version;
        // eslint-disable-next-line no-unused-vars
        interceptRequest(done, function (uri, requestBody) {
          expect(
            this.req.headers["user-agent"].startsWith(
              `atlassian-connect-express/${aceVersion}`
            )
          ).toBe(true);
        });
      });
    });

    it("get request has custom user-agent", () => {
      return new Promise(done => {
        const userAgent = "my-fun-app";
        const opts = {
          addonConfig: {
            userAgent
          }
        };
        interceptRequest(
          done,
          // eslint-disable-next-line no-unused-vars
          function (uri, requestBody) {
            expect(this.req.headers["user-agent"]).toBe(userAgent);
          },
          opts
        );
      });
    });

    it("post request preserves custom header", () => {
      return new Promise(done => {
        const interceptor = nock(clientSettings.baseUrl)
          .post("/some/path")
          // eslint-disable-next-line no-unused-vars
          .reply(function (uri, requestBody) {
            expect(this.req.headers.custom_header).toBe("arbitrary value");
          });

        getHttpClient().post(
          {
            url: "/some/path",
            headers: {
              custom_header: "arbitrary value"
            }
          },
          () => {
            interceptor.done();
            done();
          }
        );
      });
    });
  });

  describe("Add-on JWT authentication", () => {
    it("get request has Authorization header", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(done, function (uri, requestBody) {
          expect(this.req.headers.authorization).toBeDefined();
        });
      });
    });

    it("bitbucket request sets sub claim as clientKey", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(
          done,
          function () {
            const jwtToken = this.req.headers.authorization.slice(4);
            const clientKey = clientSettings.clientKey;
            const decoded = jwt.decodeSymmetric(
              jwtToken,
              clientKey,
              jwt.SymmetricAlgorithm.HS256,
              true
            );
            expect(decoded.sub).toEqual(clientKey);
          },
          {
            addonConfig: {
              product: "bitbucket"
            }
          }
        );
      });
    });

    it("Request sets iss claim as the pre-existing key", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(done, function () {
          const jwtToken = this.req.headers.authorization.slice(4);
          const clientKey = clientSettings.clientKey;
          const decoded = jwt.decodeSymmetric(
            jwtToken,
            clientKey,
            jwt.SymmetricAlgorithm.HS256,
            true
          );
          expect(decoded.iss).toEqual(clientSettings.key);
        });
      });
    });

    it('get request has Authorization header starting with "JWT "', () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(done, function (uri, requestBody) {
          expect(this.req.headers.authorization.startsWith("JWT ")).toBe(true);
        });
      });
    });

    it("get request has correct JWT qsh for encoded parameter", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(
          done,
          function () {
            const jwtToken = this.req.headers.authorization.slice(4);
            const decoded = jwt.decodeSymmetric(
              jwtToken,
              clientSettings.clientKey,
              jwt.SymmetricAlgorithm.HS256,
              true
            );
            const expectedQsh = jwt.createQueryStringHash(
              jwt.fromExpressRequest({
                method: "GET",
                path: TEST_REQUEST_URL,
                query: { q: "~ text" }
              }),
              false,
              helper.productBaseUrl
            );
            expect(decoded.qsh).toEqual(expectedQsh);
          },
          { path: `${TEST_REQUEST_URL}?q=~%20text` }
        );
      });
    });

    it("get request has correct JWT qsh for encoded parameter passed via qs field", () => {
      return new Promise(done => {
        const query = { q: "~ text" };
        // eslint-disable-next-line no-unused-vars
        interceptRequest(
          done,
          function () {
            const jwtToken = this.req.headers.authorization.slice(4);
            const decoded = jwt.decodeSymmetric(
              jwtToken,
              clientSettings.clientKey,
              jwt.SymmetricAlgorithm.HS256,
              true
            );
            const expectedQsh = jwt.createQueryStringHash(
              jwt.fromExpressRequest({
                method: "GET",
                path: TEST_REQUEST_URL,
                query
              }),
              false,
              helper.productBaseUrl
            );
            expect(decoded.qsh).toEqual(expectedQsh);
          },
          { path: TEST_REQUEST_URL, qs: query }
        );
      });
    });

    it("get request for absolute url on host has Authorization header", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(
          done,
          function () {
            expect(this.req.headers.authorization.startsWith("JWT ")).toBe(
              true
            );
          },
          {
            requestPath: `https://test.atlassian.net${TEST_REQUEST_URL}`
          }
        );
      });
    });

    it("post request has correct url", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        interceptRequest(
          done,
          function () {
            expect(this.req.headers.authorization.startsWith("JWT ")).toBe(
              true
            );
          },
          { method: "post" }
        );
      });
    });
  });

  describe("User impersonation requests", () => {
    it("Request as user does not add JWT authorization header", () => {
      return new Promise(done => {
        const authServiceMock = mocks.oauth2.service();
        // eslint-disable-next-line no-unused-vars
        interceptRequestAsUser(
          done,
          function () {
            authServiceMock.done();
            expect(this.req.headers.authorization.startsWith("JWT")).toBe(
              false
            );
          },
          { userKey: "sruiz" }
        );
      });
    });

    it("Request as user adds a Bearer authorization header", () => {
      return new Promise(done => {
        const authServiceMock = mocks.oauth2.service();
        // eslint-disable-next-line no-unused-vars
        interceptRequestAsUser(
          done,
          function () {
            authServiceMock.done();
            expect(this.req.headers.authorization.startsWith("Bearer")).toBe(
              true
            );
          },
          { userKey: "sruiz" }
        );
      });
    });

    it("Request as user adds a Bearer authorization header when using account id", () => {
      return new Promise(done => {
        const authServiceMock = mocks.oauth2.service();
        // eslint-disable-next-line no-unused-vars
        interceptRequestAsUserByAccountId(
          done,
          function () {
            authServiceMock.done();
            expect(this.req.headers.authorization.startsWith("Bearer")).toBe(
              true
            );
          },
          { userAccountId: "048abaf9-04ea-44d1-acb9-b37de6cc5d2f" }
        );
      });
    });
  });

  describe("Form requests", () => {
    it("post request with form sets form data", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        const interceptor = nock(clientSettings.baseUrl)
          .post("/some/path")
          .reply(200);

        getHttpClient()
          .post({
            url: "/some/path",
            file: [
              "file content",
              {
                filename: "filename",
                ContentType: "text/plain"
              }
            ]
          })
          .then(request => {
            expect(request.file).toEqual([
              "file content",
              { filename: "filename", ContentType: "text/plain" }
            ]);
            done();
          });
      });
    });

    it("post requests using multipartFormData have the right format", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        const interceptor = nock(clientSettings.baseUrl)
          .post("/some/path")
          .reply(200);

        const someData = "some data";
        getHttpClient()
          .post({
            url: "/some/path",
            multipartFormData: {
              file: [someData, { filename: "myattachmentagain.png" }]
            }
          })
          .then(request => {
            expect(request._form._valueLength).toEqual(someData.length);
            done();
          });
      });
    });

    it("post requests using the deprecated form parameter still have the right format", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        const interceptor = nock(clientSettings.baseUrl)
          .post("/some/path")
          .reply(200);

        const someData = "some data";
        getHttpClient()
          .post({
            url: "/some/path",
            form: {
              file: [someData, { filename: "myattachmentagain.png" }]
            }
          })
          .then(
            request => {
              expect(request._form._valueLength).toEqual(someData.length);
              done();
            },
            err => {
              console.log(err);
            }
          );
      });
    });

    it("post requests using urlEncodedFormData have the right format", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        const interceptor = nock(clientSettings.baseUrl)
          .post("/some/path")
          .reply(200);

        getHttpClient()
          .post({
            url: "/some/path",
            urlEncodedFormData: {
              param1: "value1"
            }
          })
          .then(request => {
            expect(request.body.toString()).toBe("param1=value1");
            done();
          });
      });
    });

    it("post request with undefined clientKey returns promise reject", () => {
      return new Promise(done => {
        // eslint-disable-next-line no-unused-vars
        const interceptor = nock(clientSettings.baseUrl)
          .post("/some/path")
          .reply(200);

        new HostRequest(mockAddon({}), {}, undefined)
          .post({
            url: "/some/path",
            urlEncodedFormData: {
              param1: "value1"
            }
          })
          .then(
            () => {
              // Promise is resolved
              done(new Error("Promise should not be resolved"));
            },
            // eslint-disable-next-line no-unused-vars
            reason => {
              // Promise is rejected
              done();
            }
          );
      });
    });
  });

  describe("UsingJwt() request", () => {
    it("bitbucket request sets sub claim as clientKey", () => {
      return new Promise(done => {
        interceptRequestUsingJwt(
          done,
          function () {
            const jwtToken = this.req.headers.authorization.slice(4);
            const clientKey = clientSettings.clientKey;
            const decoded = jwt.decodeSymmetric(
              jwtToken,
              clientKey,
              jwt.SymmetricAlgorithm.HS256,
              true
            );
            expect(decoded.sub).toEqual(clientKey);
          },
          {
            addonConfig: {
              product: "bitbucket"
            }
          }
        );
      });
    });

    it("Request sets iss claim as the pre-existing key", () => {
      return new Promise(done => {
        interceptRequestUsingJwt(done, function () {
          const jwtToken = this.req.headers.authorization.slice(4);
          const clientKey = clientSettings.clientKey;
          const decoded = jwt.decodeSymmetric(
            jwtToken,
            clientKey,
            jwt.SymmetricAlgorithm.HS256,
            true
          );
          expect(decoded.iss).toEqual(clientSettings.key);
        });
      });
    });

    it("get request has correct JWT qsh for encoded parameter", () => {
      return new Promise(done => {
        interceptRequestUsingJwt(
          done,
          function () {
            const jwtToken = this.req.headers.authorization.slice(4);
            const decoded = jwt.decodeSymmetric(
              jwtToken,
              clientSettings.clientKey,
              jwt.SymmetricAlgorithm.HS256,
              true
            );
            const expectedQsh = jwt.createQueryStringHash(
              jwt.fromExpressRequest({
                method: "GET",
                path: TEST_REQUEST_URL,
                query: { q: "~ text" }
              }),
              false,
              helper.productBaseUrl
            );
            expect(decoded.qsh).toEqual(expectedQsh);
          },
          { path: `${TEST_REQUEST_URL}?q=~%20text` }
        );
      });
    });

    it("get request has correct JWT qsh for encoded parameter passed via qs field", () => {
      return new Promise(done => {
        const query = { q: "~ text" };
        interceptRequestUsingJwt(
          done,
          function () {
            const jwtToken = this.req.headers.authorization.slice(4);
            const decoded = jwt.decodeSymmetric(
              jwtToken,
              clientSettings.clientKey,
              jwt.SymmetricAlgorithm.HS256,
              true
            );
            const expectedQsh = jwt.createQueryStringHash(
              jwt.fromExpressRequest({
                method: "GET",
                path: TEST_REQUEST_URL,
                query
              }),
              false,
              helper.productBaseUrl
            );
            expect(decoded.qsh).toEqual(expectedQsh);
          },
          { path: TEST_REQUEST_URL, qs: query }
        );
      });
    });

    it("get request for absolute url on host has Authorization header", () => {
      return new Promise(done => {
        interceptRequestUsingJwt(
          done,
          function () {
            expect(this.req.headers.authorization.startsWith("JWT ")).toBe(
              true
            );
          },
          {
            requestPath: `https://test.atlassian.net${TEST_REQUEST_URL}`
          }
        );
      });
    });

    it("post request has correct url", () => {
      return new Promise(done => {
        interceptRequestUsingJwt(
          done,
          function () {
            expect(this.req.headers.authorization.startsWith("JWT ")).toBe(
              true
            );
          },
          { method: "post" }
        );
      });
    });
  });

  describe("clientCredentialsGrant() requests", () => {
    it("should provide a valid error message when oauth2 is not enabled or detected", () => {
      return new Promise(done => {
        const authServiceMock = mocks.oauth2Forge.service();

        interceptRequestWithClientCredentialsGrant(
          done,
          () => {
            authServiceMock.done();
          },
          err => {
            expect(err.message).toBe(
              "oauth2 authentication is not available for this installation."
            );
            done(err);
          },
          {}
        );
      });
    });

    it("does not add JWT authorization header, but a Bearer authorization header with the api gateway host", () => {
      return new Promise(done => {
        const apiGateway = "https://api.atlassian.com";
        mocks.oauth2Forge.service();

        interceptRequestWithClientCredentialsGrant(
          done,
          function () {
            expect(this.req.headers.authorization.startsWith("JWT")).toBe(
              false
            );
            expect(this.req.headers.authorization.startsWith("Bearer")).toBe(
              true
            );
            expect(this.req.headers.host).toBe(
              apiGateway.replace("https://", "")
            );
          },
          err => {
            expect(err).toBeNull(); // to make the test failed when something wrong
          },
          {
            apiGatewayUrl: apiGateway,
            addonConfig: {
              clientSettingsOverride: extend(_.cloneDeep(clientSettings), {
                cloudId: "cloud-id",
                authentication: "oauth2"
              })
            }
          }
        );
      });
    });

    it("get request for absolute url on host has Authorization header", () => {
      return new Promise(done => {
        const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
          cloudId: "cloud-id",
          authentication: "oauth2"
        });

        const absoluteUrlBase = "https://api.atlassian.com";
        const absoluteUrlRequest = "/me";
        mocks.oauth2Forge.service();
        nock(absoluteUrlBase).get(absoluteUrlRequest).reply(200);

        getHttpClient({ clientSettingsOverride }, {})
          .clientCredentialsGrant()
          .get({
            url: `${absoluteUrlBase}${absoluteUrlRequest}`
          })
          .then(
            request => {
              expect(request.headers.host).toBe(
                absoluteUrlBase.replace("https://", "")
              );
              expect(request.path).toBe(absoluteUrlRequest);
              expect(request.headers.authorization.startsWith("Bearer")).toBe(
                true
              );
              done();
            },
            error => {
              expect(error).toBeNull();
            }
          );
      });
    });

    it("get request for absolute url on host should not have Authorization header if the url is nothing to do with the api gateway", () => {
      return new Promise(done => {
        const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
          cloudId: "cloud-id",
          authentication: "oauth2"
        });

        const absoluteUrlBase = "https://api.helloabsoluteurl.com";
        const absoluteUrlRequest = "/me";
        mocks.oauth2Forge.service();
        nock(absoluteUrlBase).get(absoluteUrlRequest).reply(200);

        getHttpClient({ clientSettingsOverride }, {})
          .clientCredentialsGrant()
          .get({
            url: `${absoluteUrlBase}${absoluteUrlRequest}`
          })
          .then(
            request => {
              expect(request.headers.host).toBe(
                absoluteUrlBase.replace("https://", "")
              );
              expect(request.path).toBe(absoluteUrlRequest);
              expect(request.headers.authorization).not.toBeDefined();
              done();
            },
            error => {
              expect(error).toBeNull();
            }
          );
      });
    });

    it("does add the non-production api gateway host for jira-dev instance", () => {
      return new Promise(done => {
        const oauth0proxy = "https://auth.stg.atlassian.com";
        const apiGatewayBaseUrl = "https://api.stg.atlassian.com";

        const authServiceMock = mocks.oauth2Forge.service(
          undefined,
          oauth0proxy
        );

        interceptRequestWithClientCredentialsGrant(
          done,
          function () {
            authServiceMock.done();
            expect(this.req.headers.host).toBe(
              apiGatewayBaseUrl.replace("https://", "")
            );
          },
          err => {
            expect(err).toBeNull();
          },
          {
            apiGatewayUrl: apiGatewayBaseUrl,
            addonConfig: {
              clientSettingsOverride: extend(_.cloneDeep(clientSettings), {
                baseUrl: "https://test-atlassian.jira-dev.com",
                cloudId: "cloud-id",
                authentication: "oauth2"
              })
            }
          }
        );
      });
    });

    describe("Form requests", () => {
      it("post request with form sets form data", () => {
        return new Promise(done => {
          const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
            cloudId: "cloud-id",
            authentication: "oauth2"
          });

          mockApiGatewayRequest(clientSettingsOverride);

          getHttpClient({ clientSettingsOverride }, {})
            .clientCredentialsGrant()
            .post({
              url: TEST_REQUEST_URL,
              file: [
                "file content",
                {
                  filename: "filename",
                  ContentType: "text/plain"
                }
              ]
            })
            .then(request => {
              expect(request.file).toEqual([
                "file content",
                { filename: "filename", ContentType: "text/plain" }
              ]);
              done();
            });
        });
      });

      it("post requests using multipartFormData have the right format", () => {
        return new Promise(done => {
          const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
            cloudId: "cloud-id",
            authentication: "oauth2"
          });

          mockApiGatewayRequest(clientSettingsOverride);

          const someData = "some data";
          getHttpClient({ clientSettingsOverride }, {})
            .clientCredentialsGrant()
            .post({
              url: TEST_REQUEST_URL,
              multipartFormData: {
                file: [someData, { filename: "myattachmentagain.png" }]
              }
            })
            .then(request => {
              expect(request._form._valueLength).toEqual(someData.length);
              done();
            });
        });
      });

      it("post requests using the deprecated form parameter still have the right format", () => {
        return new Promise(done => {
          const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
            cloudId: "cloud-id",
            authentication: "oauth2"
          });

          mockApiGatewayRequest(clientSettingsOverride);

          const someData = "some data";
          getHttpClient({ clientSettingsOverride }, {})
            .clientCredentialsGrant()
            .post({
              url: TEST_REQUEST_URL,
              form: {
                file: [someData, { filename: "myattachmentagain.png" }]
              }
            })
            .then(
              request => {
                expect(request._form._valueLength).toEqual(someData.length);
                done();
              },
              err => {
                console.log(err);
              }
            );
        });
      });

      it("post requests using urlEncodedFormData have the right format", () => {
        return new Promise(done => {
          const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
            cloudId: "cloud-id",
            authentication: "oauth2"
          });

          mockApiGatewayRequest(clientSettingsOverride);

          getHttpClient({ clientSettingsOverride }, {})
            .clientCredentialsGrant()
            .post({
              url: TEST_REQUEST_URL,
              urlEncodedFormData: {
                param1: "value1"
              }
            })
            .then(request => {
              expect(request.body.toString()).toBe("param1=value1");
              done();
            });
        });
      });
    });
  });

  describe("isClientCredentialsGrantAvailable()", () => {
    it("returns false when an authtype of the installation is NOT oauth2", async () => {
      const httpClient = getHttpClient({ clientSettings }, {});

      try {
        const result = await httpClient.isClientCredentialsGrantAvailable();
        expect(result).toEqual(false);
      } catch (err) {
        // eslint-disable-next-line jest/no-conditional-expect
        expect(err).toBeNull(); // to catch if something happens
      }
    });

    it("returns true when an authtype of the installation is oauth2", async () => {
      const clientSettingsOverride = extend(_.cloneDeep(clientSettings), {
        authentication: "oauth2"
      });

      const httpClient = getHttpClient({ clientSettingsOverride }, {});
      try {
        const result = await httpClient.isClientCredentialsGrantAvailable();
        expect(result).toEqual(true);
      } catch (err) {
        // eslint-disable-next-line jest/no-conditional-expect
        expect(err).toBeNull(); // to catch if something happens
      }
    });
  });
});
