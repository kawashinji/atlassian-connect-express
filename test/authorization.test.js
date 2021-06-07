const { authorizeJira } = require("../lib/middleware/authorization");

describe("authorizeJira", () => {
  const testUserId = "1ba2ee6a-test-account";
  function mockPermissionClient(err, globalGrants, projectGrants, errors) {
    return {
      post: (_, cb) => {
        if (err) {
          cb(err);
          return;
        }
        cb(
          undefined,
          {},
          {
            errors,
            projectPermissions: projectGrants,
            globalPermissions: globalGrants
          }
        );
      }
    };
  }

  function mockJiraRequest(userAccountId, jiraContext) {
    return {
      context: {
        userAccountId,
        // e.g. from a context JWT
        context: {
          jira: jiraContext
        }
      }
    };
  }

  it("returns 401 on permission lookup error", () => {
    return new Promise(done => {
      const addon = {
        httpClient: () => mockPermissionClient(new Error("Boom")),
        logger: {
          warn: () => {}
        }
      };
      const req = mockJiraRequest(testUserId, {});
      const res = {
        status: code => {
          expect(code).toBe(401);
          done();
          return {
            send: () => {}
          };
        }
      };
      authorizeJira(addon, {})(req, res);
    });
  });

  it("returns 401 on project permission without context set", () => {
    return new Promise(done => {
      const addon = {
        httpClient: () => mockPermissionClient(undefined),
        logger: {
          warn: () => {}
        }
      };
      const req = mockJiraRequest(testUserId, {});
      const res = {
        status: code => {
          expect(code).toBe(401);
          done();
          return {
            send: () => {}
          };
        }
      };

      authorizeJira(addon, { project: ["ADMINISTER_PROJECTS"] })(req, res);
    });
  });

  // eslint-disable-next-line jest/expect-expect
  it("calls next on authZ pass", () => {
    return new Promise(done => {
      const projectId = 10000;
      const addon = {
        httpClient: () =>
          mockPermissionClient(
            undefined,
            ["ADMINISTER"],
            [{ permissions: ["ADMINISTER_PROJECTS"], projects: [projectId] }]
          ),
        logger: {
          warn: () => {}
        }
      };
      const req = mockJiraRequest(testUserId, {
        project: {
          id: projectId
        }
      });
      const res = {};
      authorizeJira(addon, {
        global: ["ADMINISTER"],
        project: ["ADMINISTER_PROJECTS"]
      })(req, res, done);
    });
  });

  it("returns 401 on authZ check unauthorized", () => {
    return new Promise(done => {
      const addon = {
        httpClient: () => mockPermissionClient(undefined, []),
        logger: {
          warn: () => {}
        }
      };
      const req = mockJiraRequest(testUserId, {});
      const res = {
        status: code => {
          expect(code).toBe(401);
          done();
          return {
            send: () => {}
          };
        }
      };

      authorizeJira(addon, { global: ["ADMINISTER"] })(req, res);
    });
  });
});
