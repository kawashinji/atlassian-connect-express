const { isAuthorizedJira } = require("../lib/internal/authorization");

describe("isAuthorizedJira", () => {
  function mockPermissionClient(err, globalGrants, projectGrants, errors) {
    return {
      post: function (_, cb) {
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
  const testUserId = "1ba2ee6a-test-account";

  it("throws on client error", done => {
    const thrownError = new Error("failed");
    const mock = mockPermissionClient(thrownError, [], []);
    isAuthorizedJira(mock, testUserId, ["ADMINISTER"], []).catch(err => {
      expect(err).toBe(thrownError);
      done();
    });
  });

  it("throws on API response errors", done => {
    const apiError = "Unrecognized permission";
    const mock = mockPermissionClient(undefined, ["MADE_UP"], [], [apiError]);
    isAuthorizedJira(mock, testUserId, ["Unrecognized permission"], []).catch(
      err => {
        expect(err).toEqual([apiError]);
        done();
      }
    );
  });

  it("returns false if global permission missing", done => {
    const mock = mockPermissionClient(undefined, []);
    isAuthorizedJira(mock, testUserId, ["ADMINISTER"], []).then(result => {
      expect(result).toBe(false);
      done();
    });
  });

  it("returns true if global permission matched", done => {
    const mock = mockPermissionClient(undefined, ["ADMINISTER"]);
    isAuthorizedJira(mock, testUserId, ["ADMINISTER"], []).then(result => {
      expect(result).toBe(true);
      done();
    });
  });

  it("returns false if project permission missing", done => {
    const mock = mockPermissionClient(undefined, [], []);
    isAuthorizedJira(mock, testUserId, [
      { permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }
    ]).then(result => {
      expect(result).toBe(false);
      done();
    });
  });

  it("returns true if project permission matched", done => {
    const mock = mockPermissionClient(
      undefined,
      [],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }]
    );
    isAuthorizedJira(
      mock,
      testUserId,
      [],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }]
    ).then(result => {
      expect(result).toBe(true);
      done();
    });
  });

  it("returns false if project permission matched and global permission fails", done => {
    const mock = mockPermissionClient(
      undefined,
      [],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }]
    );
    isAuthorizedJira(
      mock,
      testUserId,
      ["ADMINISTER"],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }]
    ).then(result => {
      expect(result).toBe(false);
      done();
    });
  });

  it("returns false if single project permission fails", done => {
    const mock = mockPermissionClient(
      undefined,
      [],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }]
    );
    isAuthorizedJira(
      mock,
      testUserId,
      ["ADMINISTER"],
      [
        { permissions: ["ADMINISTER_PROJECTS"], projects: [10000] },
        { permissions: ["UPDATE_PROJECT"], projects: [10000] }
      ]
    ).then(result => {
      expect(result).toBe(false);
      done();
    });
  });

  it("returns false if project permission fails for given project", done => {
    const mock = mockPermissionClient(
      undefined,
      [],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000] }]
    );
    isAuthorizedJira(
      mock,
      testUserId,
      ["ADMINISTER"],
      [{ permissions: ["ADMINISTER_PROJECTS"], projects: [10000, 10001] }]
    ).then(result => {
      expect(result).toBe(false);
      done();
    });
  });

  it("returns false if project permission fails for given issue", done => {
    const mock = mockPermissionClient(
      undefined,
      [],
      [{ permissions: ["TRANSITION_ISSUES"], issues: [10000] }]
    );
    isAuthorizedJira(
      mock,
      testUserId,
      ["ADMINISTER"],
      [{ permissions: ["TRANSITION_ISSUES"], issues: [10000, 10001] }]
    ).then(result => {
      expect(result).toBe(false);
      done();
    });
  });
});
