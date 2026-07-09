## Prerequisites ##

Running midPoint node; currently supported version is 4.10.3 and later.
* On midPoint there must be a service user that has the right to access `notifyChange` REST endpoint.
* On midPoint there must be appropriately configured Active Directory resource.

### Service User

The user must have the following authorizations:

* to invoke `notifyChange` REST operation
* to read the Active Directory `ResourceType` object
* to find the shadow whose account is to be changed
* to update the shadow with the new password (and probably other changes, as computed by the sync mechanism)

For the example setup (that can be a bit hardened, as indicated in the comments) please see

* [sample role object](/sample-installation/pwd-agent-test-env/midpoint_server/container_files/mp-home/post-initial-objects/150-role-ad-pwd-sync.xml)
* [sample user object](/sample-installation/pwd-agent-test-env/midpoint_server/container_files/mp-home/post-initial-objects/210-user-ad-pwd-sync.xml)

#### Active Directory Resource Definition

The resource must be configured to process inbound password changes. Moreover, if passwords on the resource can be changed from midPoint, both directions must be enabled and mutually excluded. This can be done like this:

```xml
<credentials>
    <password>
        <inbound>
            <name>password-from-ad</name>
            <channel>http://midpoint.evolveum.com/xml/ns/public/common/channels-3#notifyChange</channel>
            <condition>
                <script>
                    <code>
                        // This is to avoid the password being cleared in later waves, when sync delta is
                        // (intentionally) not taken into account.
                        midpoint.modelContext.projectionWave == 0
                    </code>
                </script>
            </condition>
        </inbound>
        <outbound>
            <name>password-to-ad</name>
            <!-- We don't want to propagate password changes obtained via "notifyChange" mechanism back to the AD -->
            <exceptChannel>http://midpoint.evolveum.com/xml/ns/public/common/channels-3#notifyChange</exceptChannel>
        </outbound>
    </password>
</credentials>
```

See [AD resource definition](/sample-installation/pwd-agent-test-env/midpoint_server/container_files/mp-home/post-initial-objects/100-resource-ad.xml) for a full example.