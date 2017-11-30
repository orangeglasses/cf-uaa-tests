# cf-uaa-tests
Contains a number of automated tests against CloudFoundry UAA. This is not readily runnable code. This code needs to be incorporated into a Go micro service that is bound to the Pivotal CloudFoundry `p-identity` service.

The tests expect a bound `p-identity` client app that has `scim.write` and `scim.read` authority to be able to create a temporary user that is used for some of the tests. To update this `p-identity` client to have the correct authorities, use the following `uaac` command line:

    uaac token client get admin -s "<adminsecret>"
    uaac client update <clientid> --authorities "scim.write,scim.read,uaa.resource"

First obtain a valid administrator token for UAA (`<adminsecret>` is environment-specific). Next update the `p-identity` client to have the required authorities.