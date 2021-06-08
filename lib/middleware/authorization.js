const { isAuthorizedJira } = require("../internal/authorization");

/**
 * Authorize the current request against Jira using the current user
 * The "current issue" and "current project" are used as inputs into the API
 * e.g. app.get('/example', [addon.authenticate(), addon.authorizeJira({ global: ["ADMINISTER"]})]) ...
 */
function authorizeJira(addon, permissions) {
  return function (req, res, next) {
    const accountId = req.context.userAccountId;
    const jiraContext = req.context.context.jira || {};
    const currentProject = jiraContext.project || {};
    const currentIssue = jiraContext.issue || {};
    const projectPermissions = permissions.project || [];
    const globalPermissions = permissions.global || [];

    // missing context
    if (projectPermissions && (!currentProject.id || !currentProject.id)) {
      addon.logger.warn("Authorization failed");
      res.status(401).send("Unauthorized: permissions could not be determined");
      return;
    }

    const projectPermissionLookup =
      projectPermissions.length > 0
        ? [
            {
              permissions: projectPermissions,
              projects: currentProject.id ? [currentProject.id] : [],
              issues: currentIssue.id ? [currentIssue.id] : []
            }
          ]
        : [];

    console.log(projectPermissionLookup);

    const httpClient = addon.httpClient(req);
    isAuthorizedJira(
      httpClient,
      accountId,
      globalPermissions,
      projectPermissionLookup
    )
      .then(result => {
        if (result) {
          next();
          return;
        }

        res.status(401).send("Unauthorized");
      })
      .catch(err => {
        addon.logger.warn("Authorization check failed", err);
        res
          .status(401)
          .send("Unauthorized: permissions could not be determined");
      });
  };
}

module.exports = {
  authorizeJira
};
