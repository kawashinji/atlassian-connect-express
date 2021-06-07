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
      function (err, _, body) {
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

    for (const grantedProjectPermission of grants.projectPermissions) {
      if (
        projectPermission.permission === grantedProjectPermission.permission &&
        _.isEqual(
          _.sortBy(projectPermission.projects),
          _.sortBy(grantedProjectPermission.projects)
        ) &&
        _.isEqual(
          _.sortBy(projectPermission.issues),
          _.sortBy(grantedProjectPermission.issues)
        )
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
  ).then(function (grants) {
    return checkGrantsSatisify(grants, globalPermissions, projectPermissions);
  });
}

module.exports = {
  isAuthorized
};
