# su-binary
su binary for Android

This su binary:

1: Replace "fifos" by "pipes" (and send_fd()/recv_fd() the created pipes from the client to the daemon through socket) to get rid of SELinux.

2: For Terminal Emulators: Open "/dev/ptmx" device on daemon instead of (stealing the TTY'S STDIN on daemon's child via "ioctl(infd, TIOCSCTTY, 1);" will cause unpected warning on su's exit by "/system/bin/sh") on the client. Use the created "pipe" to send data/commands from client's STDIN to daemon's "pipe" (will be read and pumped to "/dev/ptmx") and pump() command's STDOUT/STDERR from daemon's opened PTY to client. Prior to sending/receiving data, Changes the TTY's stdin to raw unbuffered mode, disables echo,  auto carriage return, etc.

3: Skips APK communication/connection.
