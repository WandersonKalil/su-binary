# su-binary
su binary for Android

This su binary:

1: Replace "fifos" by "pipes" (and send_fd()/recv_fd() the created pipes from the client to the daemon through socket) to get rid of SELinux.

2: Skips APK communication/connection.
