# cf-uaa-tests
Contains a number of automated tests against CloudFoundry UAA. This is not readily runnable code. This code needs to be incorporated into a Go micro service that is bound to the Pivotal CloudFoundry `p-identity` service.

The tests expect a bound `p-identity` client app that has `scim.write` and `scim.read` authority to be able to create a temporary user that is used for some of the tests. To update this `p-identity` client to have the correct authorities, use the following `uaac` command line:

    uaac token client get admin -s "<adminsecret>"
    uaac client update <clientid> --authorities "scim.write,scim.read,uaa.resource"

First obtain a valid administrator token for UAA (`<adminsecret>` is environment-specific). Next update the `p-identity` client to have the required authorities.

### Code organization
The repository contains code for two applications: a server-side component with the entrypoint in `serverSso.go` and a client side component in `clientSso.go`. The client is a simple Go web application that exposes two endpoints, both protected by UAA. This client expects to be bound to two `p-identity` service instances.

### Tests
The server component runs the following tests:
- perform an OAuth2 client credentials grant against Pivotal UAA. The client that is authenticated against must have `scim.write` and `scim.read` scopes.
- Create a (temporary) internal UAA user and add it to a specific scope (in this case: `smoketest.extinguish`).

    The `smoketest.extinguish` scope can be added to UAA via the following command line:

      uaac group add "smoketest.extinguish"

- Authenticate newly created user against UAA using OAuth2 password grant.
- Authenticate newly created user against the `clientSso.go` app using OAuth2 authorization code grant. This test attempts to access the `/uaaLogin` endpoint of the `clientSso.go` app.
- Authenticate (existing) AD user against the `clientSso.go` app using OAuth2 authorization code grant. This test attempts to access the `/adfsLogin` endpoint of the `clientSso.go` app.

Note that for the last test to succeed, UAA must be configured to delegate authentication against an external ADFS service.

The final two tests attempt to access the `clientSso.go` app emulating a browser. So these tests send an http request to the relevant endpoint, follow all redirects to a login form and parse the login form to be able to emulate a login.

### Client code
As mentioned before, the client exposes two endpoints. The client must therefore bound to two `p-identity` services. The expected service names are `smoketests-sso-uaa` and `smoketests-sso-adfs`.