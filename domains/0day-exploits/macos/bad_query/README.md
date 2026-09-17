# bad_query

### A sandbox escape for iOS 26.0 - 26.6.1 / 27.0b4.

This is a proof-of-concept for developers and not anything meaningfully usable at the moment.

bad_query can access the following paths:

```
/var/containers/Data/System (iOS 27)
/var/containers/Shared/SystemGroup/* (iOS 27)
/var/mobile/Containers/Data/Application/*
/var/mobile/Containers/Data/InternalDaemon/*
/var/mobile/Containers/Data/PluginKitPlugin/*
/var/mobile/Containers/Shared/AppGroup/* (Requires App Group sacrifice on iOS 26)
/var/mobile/Containers/Shared/AppGroup (iOS 27)
```

<sub>This might also work on iOS 18 but I haven't tested literally at all so ymmv</sub>
