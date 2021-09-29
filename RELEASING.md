# Release process

Pre-requisites: be an owner of https://npmjs.org/package/atlassian-connect-express
(#help-connect)

1. Create a new release branch from master 
    ```
      > git checkout master
      > git pull
      > git checkout -b release/x.x.x
    ```
2. Update [release notes](./RELEASENOTES.md) 

3. Update the version using by running `npm version` command with appropriate versioning semantic. 

    ```
      npm version (major|minor|patch|prerelease)
    ```
    This will simply bump the `version` in the package.json file and commit the changes.

4. Publish the new version
    ```
    npm publish
    ```
