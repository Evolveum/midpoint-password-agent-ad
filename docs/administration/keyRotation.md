## Key rotation mechanism procedure ##

- Application reads the name of the latest key version from the Win Registry (e.g. v2)
- Creates the name of the new version (v3)
- Generates the value of the new key
- Writes the new key to the Win Registry
- Sets the new key as current (from this moment the Listener (Windows LSA Password Notification Filter) can use it)
- Application finds all .event files that were encrypted with the "previous" key and re-encrypts them using the new key.
- New key version is stored in file name.