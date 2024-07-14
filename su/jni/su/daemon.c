/*
** Copyright 2010, Adam Shanks (@ChainsDD)
** Copyright 2008, Zinx Verituse (@zinxv)
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define _GNU_SOURCE /* for unshare() */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <termios.h>
#include <sys/syscall.h>

//#ifdef SUPERUSER_EMBEDEDED
#include "cutils/multiuser.h"
//#endif

#include "su.h"
#include "utils.h"

int is_daemon = 0;
int daemon_from_uid = 0;
int daemon_from_pid = 0;

/*
 * Receive a file descriptor from a Unix socket.
 * Contributed by @mkasick
 *
 * Returns the file descriptor on success, or -1 if a file
 * descriptor was not actually included in the message
 *
 * On error the function terminates by calling exit(-1)
 */
static int recv_fd(int sockfd) {
    // Need to receive data from the message, otherwise don't care about it.
    char iovbuf;

    struct iovec iov = {
        .iov_base = &iovbuf,
        .iov_len  = 1,
    };

    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    if (recvmsg(sockfd, &msg, MSG_WAITALL) != 1) {
        goto error;
    }

    // Was a control message actually sent?
    switch (msg.msg_controllen) {
    case 0:
        // No, so the file descriptor was closed and won't be used.
        return -1;
    case sizeof(cmsgbuf):
        // Yes, grab the file descriptor from it.
        break;
    default:
        goto error;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg             == NULL                  ||
        cmsg->cmsg_len   != CMSG_LEN(sizeof(int)) ||
        cmsg->cmsg_level != SOL_SOCKET            ||
        cmsg->cmsg_type  != SCM_RIGHTS) {
error:
        LOGE("unable to read fd");
        exit(-1);
    }

    return *(int *)CMSG_DATA(cmsg);
}

/*
 * Send a file descriptor through a Unix socket.
 * Contributed by @mkasick
 *
 * On error the function terminates by calling exit(-1)
 *
 * fd may be -1, in which case the dummy data is sent,
 * but no control message with the FD is sent.
 */
static void send_fd(int sockfd, int fd) {
    // Need to send some data in the message, this will do.
    struct iovec iov = {
        .iov_base = "",
        .iov_len  = 1,
    };

    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
    };

    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    if (fd != -1) {
        // Is the file descriptor actually open?
        if (fcntl(fd, F_GETFD) == -1) {
            if (errno != EBADF) {
                goto error;
            }
            // It's closed, don't send a control message or sendmsg will EBADF.
        } else {
            // It's open, send the file descriptor in a control message.
            msg.msg_control    = cmsgbuf;
            msg.msg_controllen = sizeof(cmsgbuf);

            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

            cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type  = SCM_RIGHTS;

            *(int *)CMSG_DATA(cmsg) = fd;
        }
    }

    if (sendmsg(sockfd, &msg, 0) != 1) {
error:
        PLOGE("unable to send fd");
        exit(-1);
    }
}


static int read_int(int fd) {
    int val;
    int len = read(fd, &val, sizeof(int));
    if (len != sizeof(int)) {
        LOGE("unable to read int");
        exit(-1);
    }
    return val;
}

static void write_int(int fd, int val) {
    int written = write(fd, &val, sizeof(int));
    if (written != sizeof(int)) {
        PLOGE("unable to write int");
        exit(-1);
    }
}

static char* read_string(int fd) {
    int len = read_int(fd);
    if (len > PATH_MAX || len < 0) {
        LOGE("invalid string length %d", len);
        exit(-1);
    }
    char* val = malloc(sizeof(char) * (len + 1));
    if (val == NULL) {
        LOGE("unable to malloc string");
        exit(-1);
    }
    val[len] = '\0';
    int amount = read(fd, val, len);
    if (amount != len) {
        LOGE("unable to read string");
        exit(-1);
    }
    return val;
}

static void write_string(int fd, char* val) {
    int len = strlen(val);
    write_int(fd, len);
    int written = write(fd, val, len);
    if (written != len) {
        PLOGE("unable to write string");
        exit(-1);
    }
}


// WK, added on 02/11/2022: support mount namespace:
// Missing system call wrappers

int setns(int fd, int nstype) {
    return syscall(__NR_setns, fd, nstype);
}

int unshare(int flags) {
    return syscall(__NR_unshare, flags);
}

static void MountAppDataTmpFs(const char *target_dir) {
 
  if (mount("tmpfs", target_dir, "tmpfs",
                               MS_NOSUID | MS_NODEV | MS_NOEXEC, "uid=0,gid=0,mode=0751") == -1) {
    PLOGE("Failed to mount tmpfs to %s: %s", target_dir, strerror(errno));
  }
}


/*static*/ void switch_mnt_ns(int pid) {
     char mnt[PATH_MAX];
	/*if (su_ctx && su_ctx->enablemountnamespaceseparation == 0) {
		return;
	} else {*/
        snprintf(mnt, sizeof(mnt), "/proc/%d/ns/mnt", pid);
	//}
	//} else {
	 // WK added on 07/03/2023: if the daemon is started from SuperPower or Terminal Emulator, it will inherit the mount namespace of SuperPower or Terminal Emulator (even if we kill and start the daemon) when using --mount-master, breaking file managers apps which expect the whole view of files(/data/data/*).
     // to fix this unexpected behavior without rebooting the phone, we need to switch to init's mount namespace.
	 //snprintf(mnt, sizeof(mnt), "/proc/1/ns/mnt");
    //}
	
	LOGD("mnt_ns: %s", mnt);

    int fd, ret;
    fd = open(mnt, O_RDONLY);
    if (fd < 0) {//return 1;
	PLOGE("open()");
        // Create a second private mount namespace for our process
        if (unshare(CLONE_NEWNS) < 0) {
            PLOGE("unshare");
            return;
        }

        if (mount(NULL/*"rootfs"*/, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
            PLOGE("mount rootfs as slave");
            return;
        }
    } else {
		// /data/data/* is not shown without this.
       // Switch to its namespace
       ret = setns(fd, 0);
       if (ret < 0) {   
	       PLOGE("setns(): %d", ret);
	   }
        close(fd);
    }
    //return ret;
}


#define AID_USER_OFFSET 100000 /* offset for uid ranges for each user */

userid_t multiuser_get_user_id(uid_t uid) {
    return uid / AID_USER_OFFSET;
}
//#ifdef SUPERUSER_EMBEDDED
static void mount_emulated_storage(int user_id) {
    const char *emulated_source = getenv("EMULATED_STORAGE_SOURCE");
    const char *emulated_target = getenv("EMULATED_STORAGE_TARGET");
    const char* legacy = getenv("EXTERNAL_STORAGE");

    char user_source[PATH_MAX];
	
    if (!emulated_source || !emulated_target) {
        // No emulated storage is present
		LOGW("No emulated storage is present: %s %s %s", emulated_source, emulated_target, legacy);
        //return;
    }

    // Create a second private mount namespace for our process
    if (unshare(CLONE_NEWNS) < 0) {
        PLOGE("unshare");
        return;
    }

    if (mount("/"/*"rootfs"*/, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
        PLOGE("mount rootfs as slave");
        return;
    }

	if (emulated_source && *emulated_source && emulated_target && *emulated_target) {
    // /mnt/shell/emulated -> /storage/emulated
    if (mount(emulated_source, emulated_target, NULL, MS_BIND, NULL) < 0) {
        PLOGE("mount emulated storage");
    }

    char target_user[PATH_MAX];
    snprintf(target_user, PATH_MAX, "%s/%d", emulated_target, user_id);

    // /mnt/shell/emulated/<user> -> /storage/emulated/legacy
    if (mount(target_user, legacy, NULL, MS_BIND | MS_REC, NULL) < 0) {
        PLOGE("mount legacy path");
    } else {
		LOGD("sdcard mounted: %s", target_user);
	}
   } else {
	   
	 snprintf(user_source, PATH_MAX, "/mnt/user/%d", user_id);

    // /mnt/shell/emulated/<user> -> /storage/emulated/legacy
    if (mount(user_source, legacy, NULL, MS_BIND | MS_REC, NULL) < 0) {
        PLOGE("mount legacy path");
    } else {
		LOGD("storage mounted: %s", user_source);
	}
   }
   
   
  /* if (mount("/data/data", "/data/data", NULL, MS_BIND | MS_REC, NULL) < 0) {
        PLOGE("mount legacy path");
    } */
   //MountAppDataTmpFs("/data/data/");
   
}
//#endif

static int run_daemon_child(int infd, int outfd, int errfd, int argc, char** argv) {
    if (-1 == dup2(outfd, STDOUT_FILENO)) {
        PLOGE("dup2 child outfd");
        exit(-1);
    }

    if (-1 == dup2(errfd, STDERR_FILENO)) {
        PLOGE("dup2 child errfd");
        exit(-1);
    }

    if (-1 == dup2(infd, STDIN_FILENO)) {
        PLOGE("dup2 child infd");
        exit(-1);
    }

    close(infd);
    close(outfd);
    close(errfd);

    return su_main(argc, argv, 0);
}

static void pump(int input, int output, int who) {
    char buf[4096];
    int len;
	memset(buf, 0, sizeof(buf));
	buf[sizeof(buf) -1] = '\0';
	
    while ((len = read(input, buf, 4096)) > 0) {
        write(output, buf, len);
		//LOGD("from [%d %s]: %s", who, (who == 1) ? "daemon" : "client", buf);
    }
    close(input);
    close(output);
}

static void* pump_thread(void* data) {
    int* files = (int*)data;
    int input = files[0];
    int output = files[1];
	int who = files[2];
    pump(input, output, who);
    free(data);
    return NULL;
}

static void pump_async(int input, int output, int who) {
    pthread_t writer;
    int* files = (int*)malloc(sizeof(int) * 3);
    if (files == NULL) {
        LOGE("unable to pump_async");
        exit(-1);
    }
    files[0] = input;
    files[1] = output;
	files[2] = who;
    pthread_create(&writer, NULL, pump_thread, files);
}

static int daemon_accept(int fd) {
    is_daemon = 1;
    int pid = read_int(fd);
    LOGD("remote pid: %d", pid);
    int atty = read_int(fd);
    LOGD("remote atty: %d", atty);
    daemon_from_uid = read_int(fd);
    LOGD("remote uid: %d", daemon_from_uid);
    daemon_from_pid = read_int(fd);
    LOGD("remote req pid: %d", daemon_from_pid);

    struct ucred credentials;
    socklen_t ucred_length = sizeof(credentials);
    /* fill in the user data structure */
    if(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &ucred_length)) {
        LOGE("could obtain credentials from unix domain socket");
        exit(-1);
    }
    // if the credentials on the other side of the wire are NOT root,
    // we can't trust anything being sent.
    if (credentials.uid != 0) {
        daemon_from_uid = credentials.uid;
        //pid = credentials.pid;
        //daemon_from_pid = credentials.pid;
    }
	
    int mount_storage = read_int(fd);
	
	// The the FDs for each of the streams
    int infd  = recv_fd(fd);
	int outfd = recv_fd(fd);
    int errfd = recv_fd(fd);
	
    int argc = read_int(fd);
    if (argc < 0 || argc > 512) {
        LOGE("unable to allocate args: %d", argc);
        exit(-1);
    }
    LOGD("remote args: %d", argc);
    char** argv = (char**)malloc(sizeof(char*) * (argc + 1));
    argv[argc] = NULL;
    int i;
    for (i = 0; i < argc; i++) {
        argv[i] = read_string(fd);
    }
/*

    // WK: on 11/07/2024: Using fifos will invoke SELinux deny permissions on client's 
	// open/read/write of fifos due to tmps /dev/ (we opening fifos out of our client's process's namespace). 
	// Replaced fifos by pipes: send/receive open fd through socket via send_fd/recv.
   
	char errfile[PATH_MAX];
    char outfile[PATH_MAX];
    char infile[PATH_MAX];
    sprintf(outfile, "%s/%d.stdout", REQUESTOR_DAEMON_PATH, pid);
    sprintf(errfile, "%s/%d.stderr", REQUESTOR_DAEMON_PATH, pid);
    sprintf(infile, "%s/%d.stdin", REQUESTOR_DAEMON_PATH, pid);

    if (mkfifo(outfile, 0660) != 0) {
        PLOGE("mkfifo %s", outfile);
        exit(-1);
    }
    if (mkfifo(errfile, 0660) != 0) {
        PLOGE("mkfifo %s", errfile);
        unlink(outfile);
        exit(-1);
    }
    if (mkfifo(infile, 0660) != 0) {
        PLOGE("mkfifo %s", infile);
        unlink(errfile);
        unlink(outfile);
        exit(-1);
    }

    chown(outfile, daemon_from_uid, 0);
    chown(infile, daemon_from_uid, 0);
    chown(errfile, daemon_from_uid, 0);
    chmod(outfile, 0660);
    chmod(infile, 0660);
    chmod(errfile, 0660);
*/
    // ack
    write_int(fd, 1);

    int ptm = -1;
    char* devname = NULL;
    if (atty) {
        ptm = open("/dev/ptmx", O_RDWR);
        if (ptm <= 0) {
            PLOGE("ptm");
			exit(-1);
            //goto unlink_n_exit;
        }
        if(grantpt(ptm) || unlockpt(ptm) || ((devname = (char*) ptsname(ptm)) == 0)) {
            PLOGE("ptm setup");
            close(ptm);
        /*unlink_n_exit:
            unlink(infile);
            unlink(errfile);
            unlink(outfile);*/
            exit(-1);
        }
        LOGD("devname: %s", devname);
		//send_fd(fd, ptm);
    }
/* 
    // WK: on 11/07/2024: Using fifos will invoke SELinux deny permissions on client's 
	// open/read/write of fifos due to tmps /dev/ (we opening fifos out of our client's process's namespace). 
	// Replaced fifos by pipes: send/receive open fd through socket via send_fd/recv_fd.
    // we do not need this when using pipes.
    int outfd = open(outfile, O_WRONLY);
    if (outfd <= 0) {
        PLOGE("outfd daemon %s", outfile);
        goto unlink_n_exit;
    }
    int errfd = open(errfile, O_WRONLY);
    if (errfd <= 0) {
        PLOGE("errfd daemon %s", errfile);
        goto unlink_n_exit;
    }
    int infd = open(infile, O_RDONLY);
    if (infd <= 0) {
        PLOGE("infd daemon %s", infile);
        goto unlink_n_exit;
    }

    // Wait for client to open pipes, then remove
    read_int(fd);
    unlink(infile);
    unlink(errfile);
    unlink(outfile);
*/
    int code;
    // now fork and run main, watch for the child pid exit, and send that
    // across the control channel as the response.
    int child = fork();
    if (child < 0) {
        code = child;
        goto done;
    }

    // if this is the child, open the fifo streams
    // and dup2 them with stdin/stdout, and run main, which execs
    // the target.
    if (child == 0) {
        close(fd);

        if (devname != NULL) {
             
            setsid();
			
			int pts = open(devname, O_RDWR);
            if(pts < 0) {
                PLOGE("pts");
                exit(-1);
            }

            struct termios slave_orig_term_settings; // Saved terminal settings 
            tcgetattr(pts, &slave_orig_term_settings);

            struct termios new_term_settings;
            new_term_settings = slave_orig_term_settings; 
            cfmakeraw(&new_term_settings);
            // WHY DOESN'T THIS WORK, FUUUUU
            new_term_settings.c_lflag &= ~(ECHO);
		
            tcsetattr(pts, TCSANOW, &new_term_settings);
         
            ioctl(pts, TIOCSCTTY, 1);

            close(infd);
            close(outfd);
            close(errfd);
            close(ptm);

            errfd = pts;
            infd = pts;
            outfd = pts;
        }

		//switch_mnt_ns(daemon_from_pid);
//#ifdef SUPERUSER_EMBEDEDED
       // if (mount_storage) {
            mount_emulated_storage(multiuser_get_user_id(daemon_from_uid));
        //}
//#endif

        return run_daemon_child(infd, outfd, errfd, argc, argv);
    }
    
    if (devname != NULL) {
        // pump ptm across the socket
        pump_async(infd, ptm, 1);
        pump(ptm, outfd, 1);
    }
    else {
        close(infd);
        close(outfd);
        close(errfd);
    }

    // wait for the child to exit, and send the exit code
    // across the wire.
    int status;
    LOGD("waiting for child exit %d", child);
    if (waitpid(child, &status, 0) > 0) {
        if (WIFEXITED(status)) {
            code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            code = 128 + WTERMSIG(status);
        } else {
            code = -1;
        }
    }
    else {
        code = -1;
    }

done:
    write(fd, &code, sizeof(int));
    close(fd);
    LOGD("child exited");
    return code;
}

int run_daemon() {
    if (getuid() != 0 || getgid() != 0) {
        PLOGE("daemon requires root. uid/gid not root");
        return -1;
    }
		
    int fd;
    struct sockaddr_un sun;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        PLOGE("socket");
        return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        PLOGE("fcntl FD_CLOEXEC");
        goto err;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
    sprintf(sun.sun_path, "%s/server", REQUESTOR_DAEMON_PATH);

    /*
     * Delete the socket to protect from situations when
     * something bad occured previously and the kernel reused pid from that process.
     * Small probability, isn't it.
     */
    unlink(sun.sun_path);
    unlink(REQUESTOR_DAEMON_PATH);

    int previous_umask = umask(027);
    mkdir(REQUESTOR_DAEMON_PATH, 0777);

	memset(sun.sun_path, 0, sizeof(sun.sun_path));
    memcpy(sun.sun_path, "\0" "SUPERUSER", strlen("SUPERUSER") + 1);

    if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
        PLOGE("daemon bind");
        goto err;
    }

    chmod(REQUESTOR_DAEMON_PATH, 0755);
    chmod(sun.sun_path, 0777);

    umask(previous_umask);

    if (listen(fd, 10) < 0) {
        PLOGE("daemon listen");
        goto err;
    }

    int client;
    while ((client = accept(fd, NULL, NULL)) > 0) {
        if (fork_zero_fucks() == 0) {
            close(fd);
            return daemon_accept(client);
        }
        else {
            close(client);
        }
    }

    LOGE("daemon exiting");
err:
    close(fd);
    return -1;
}

// Stores the previous termios of stdin
static struct termios old_stdin;
static int stdin_is_raw = 0;

/**
 * set_stdin_raw
 *
 * Changes stdin to raw unbuffered mode, disables echo, 
 * auto carriage return, etc.
 *
 * Return Value
 * on failure -1, and errno is set
 * on success 0
 */
static void set_stdin_raw(void) {
    struct termios new_termios;

    // Save the current stdin termios
    if (tcgetattr(STDIN_FILENO, &old_stdin) < 0) {
		PLOGE("tcgetattr(STDIN_FILENO, &old_stdin)");
        //return -1;
    }

    // Start from the current settings
    new_termios = old_stdin;

    // Make the terminal like an SSH or telnet client
    new_termios.c_iflag |= IGNPAR;
    new_termios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
    new_termios.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
    // WK: on 24/07/2024: this line is not needed and will cause unpected behavior on stderr after failed command
	//new_termios.c_oflag &= ~OPOST;
    new_termios.c_cc[VMIN] = 1;
    new_termios.c_cc[VTIME] = 0;

	// WK: on 13/07/2024: The TCSAFLUSH will fail with : "22: invalid argument" on Android 14.
    if (tcsetattr(STDIN_FILENO, TCSANOW/*TCSAFLUSH*/, &new_termios) < 0) {
		PLOGE("tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_stdin)");
        //return -1;
    }

    stdin_is_raw = 1;

   // return 0;
}

int connect_daemon(int argc, char *argv[]) {
  /*  char errfile[PATH_MAX];
    char outfile[PATH_MAX];
    char infile[PATH_MAX];*/
    int uid = getuid();
   /* sprintf(outfile, "%s/%d.stdout", REQUESTOR_DAEMON_PATH, getpid());
    sprintf(errfile, "%s/%d.stderr", REQUESTOR_DAEMON_PATH, getpid());
    sprintf(infile, "%s/%d.stdin", REQUESTOR_DAEMON_PATH, getpid());
*/

    int infd[2];
	int outfd[2];
	int errfd[2];
	
    struct sockaddr_un sun;

    int socketfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (socketfd < 0) {
        PLOGE("socket");
        exit(-1);
    }
    if (fcntl(socketfd, F_SETFD, FD_CLOEXEC)) {
        PLOGE("fcntl FD_CLOEXEC");
        exit(-1);
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
    sprintf(sun.sun_path, "%s/server", REQUESTOR_DAEMON_PATH);

	memset(sun.sun_path, 0, sizeof(sun.sun_path));
    memcpy(sun.sun_path, "\0" "SUPERUSER", strlen("SUPERUSER") + 1);

    if (0 != connect(socketfd, (struct sockaddr*)&sun, sizeof(sun))) {
        PLOGE("connect");
        exit(-1);
    }

    LOGD("connecting client %d", getpid());

    int mount_storage = getenv("MOUNT_EMULATED_STORAGE") != NULL;

    write_int(socketfd, getpid());
    write_int(socketfd, isatty(STDIN_FILENO));
    write_int(socketfd, uid);
    write_int(socketfd, getppid());
    write_int(socketfd, mount_storage);
	
	if (pipe(infd) < 0) {
		PLOGE("pipe(infd)");
		exit(-1);
	} else {
		LOGD("infd pipes are open: [%d][%d]", infd[0], infd[1]);
		// Send stdin
		send_fd(socketfd, infd[0]/*STDIN_FILENO*/);
	}
	
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, outfd) < 0) {
        PLOGE("socketpair()");
		exit(-1);
	} else {
		LOGD("outfd pipes/sockets are open: [%d][%d]", outfd[0], outfd[1]);
		// Send stdout
		send_fd(socketfd, outfd[1]/*STDOUT_FILENO*/);
	}
	
	if (pipe(errfd) < 0) {
		PLOGE("pipe(errfd)");
		exit(-1);
	} else {
		LOGD("errfd pipes are open: [%d][%d]", errfd[0], errfd[1]);
		// Send stderr
		send_fd(socketfd, errfd[1]/*STDERR_FILENO*/);
	}
	
    write_int(socketfd, mount_storage ? argc - 1 : argc);

    int i;
    for (i = 0; i < argc; i++) {
        if (i == 1 && mount_storage) {
            continue;
        }
        write_string(socketfd, argv[i]);
    }

    // ack
    read_int(socketfd);
	
	// WK: on 11/07/2024: Using fifos will invoke SELinux deny permissions on client's 
	// open/read/write (SELinux will not allow patching the "write" permission on Android 14) of fifos due to tmps /dev/ (we opening fifos out of our client's process's namespace). 
	// Replaced fifos by pipes: send/receive open fd through socket via send_fd()/recv_fd().
    /*
    int outfd = open(outfile, O_RDONLY);
    if (outfd <= 0) {
        PLOGE("outfd %s ", outfile);
        exit(-1);
    }
	
	LOGD("client's fifo %s outfd is open:[%d]", outfile,  outfd);
	
    int errfd = open(errfile, O_RDONLY);
    if (errfd <= 0) {
        PLOGE("errfd %s", errfile);
        exit(-1);
    }
	LOGD("client's fifo %s errfd is open:[%d]", errfile,  errfd);
	
    int infd = open(infile, O_WRONLY);
    if (infd <= 0) {
        PLOGE("infd %s", infile);
        exit(-1);
    }*/
    
    // notify daemon that the pipes are open.
    //write_int(socketfd, 1);
	
	//int ptmx = recv_fd(socketfd);
	
	/*struct termios slave_orig_term_settings; // Saved terminal settings 
    tcgetattr(STDIN_FILENO, &slave_orig_term_settings);

    struct termios new_term_settings;
    new_term_settings = slave_orig_term_settings; 
    // Put stdin into raw mode: note: this disables stdin's echo on stdout, 
	// but introduces a new subtle bug on stderr for failed commands.
	//cfmakeraw(&new_term_settings);
	// this line is uneeded. if used alone, it will hide the input typed on tty's stdin. xy3h2
    // WHY DOESN'T THIS WORK, FUUUUU
    new_term_settings.c_lflagx &= ~(ECHO);
	
	//new_term_s ettings.c_oflag &= ~OPOST;
    new_term_settings.c_cc[VMIN] = 1;
    new_term_settings.c_cc[VTIME] = 0;
	
	tcsetattr(STDIN_FILENO, TCSANOW, &new_term_settings);
    */
	
	set_stdin_raw();
	
	close(infd[0]);
	close(outfd[1]);
	close(errfd[1]);
	
    pump_async(STDIN_FILENO, infd[1], 0);
    pump_async(errfd[0], STDERR_FILENO, 0);
	pump(outfd[0], STDOUT_FILENO, 0);
	
    int code = read_int(socketfd);
    close(socketfd);
	
	close(infd[1]);
    close(outfd[0]);
    close(errfd[0]);
	
	// Cleanup
	// Restore termios on stdin to the state it was before
    // set_stdin_raw() was called.
    if (tcsetattr(STDIN_FILENO, TCSANOW/*TCSAFLUSH*/, &old_stdin) < 0) {
        PLOGE("tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_stdin)");
		//return -1;
    } else {
		stdin_is_raw = 0;
	}
	
	//ioctl(STDIN_FILENO, TIOCSCTTY, 1);
	
    LOGD("client exited %d", code);
	
    return code;
}
