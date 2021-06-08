const _ = require("lodash");

function getGrants(
  httpClient,
  accountId,
  globalPermissions,
  projectPermissions
) {
  return new Promise((resolve, reject) =>
    httpClient.post(
      {
        url: "/rest/api/3/permissions/check",
        headers: {
          "X-Atlassian-Token": "nocheck"
        },
        json: {
          globalPermissions,
          projectPermissions,
          accountId
        }
      },
      (err, _, body) => {
        if (err) {
          reject(err);
          return;
        }

        if (body.errors) {
          reject(body.errors);
          return;
        }

        if (body.errorMessages) {
          reject(body.errorMessages);
          return;
        }

        resolve({
          projectPermissions: body.projectPermissions || [],
          globalPermissions: body.globalPermissions || []
        });
      }
    )
  );
}

// Normalizes the given array such that all elements are strings, and in sorting order. This is useful for comparing project/issue ids consistently.
function normalize(a) {
  return _.sortBy(_.map(a, item => item.toString()));
}

function checkGrantsSatisify(
  grants,
  requiredGlobalPermissions,
  requiredProjectPermissions
) {
  // If an invalid permission is requested checking for equality will ensure no match is made
  if (
    !_.isEqual(
      _.sortBy(grants.globalPermissions),
      _.sortBy(requiredGlobalPermissions)
    )
  ) {
    return false;
  }

  for (const projectPermission of requiredProjectPermissions) {
    let satisifed = false;
    const projectIds = normalize(projectPermission.projects);
    const issueIds = normalize(projectPermission.issues);

    for (const grantedProjectPermission of grants.projectPermissions) {
      if (
        projectPermission.permission === grantedProjectPermission.permission &&
        _.isEqual(projectIds, normalize(grantedProjectPermission.projects)) &&
        _.isEqual(issueIds, normalize(grantedProjectPermission.issues))
      ) {
        satisifed = true;
        break;
      }
    }

    if (!satisifed) {
      return false;
    }
  }

  return true;
}

/**
 * Determins if the given account satisfies the requested permissions
 */
function isAuthorized(
  httpClient,
  accountId,
  globalPermissions,
  projectPermissions
) {
  return getGrants(
    httpClient,
    accountId,
    globalPermissions,
    projectPermissions
  ).then(grants =>
    checkGrantsSatisify(grants, globalPermissions, projectPermissions)
  );
}

module.exports = {
  isAuthorized
};
