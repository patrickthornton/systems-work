// sandbox.c
//
// usage: sandbox <path> <uid>
//
// a simple sandboxer to restrict the execution of a given python script.
// <path> is the directory to the python script; <uid> is the user id whose
// privilege should be used to execute the script.

#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// constants for data structures
#define STACK_SIZE 65536
#define TABLE_SIZE 3

// macros to help differentiate ptrace-stops
#define WIFCLONE(status) (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
#define WIFFORK(status) (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)))
#define WIFVFORK(status) (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
#define WIFSYSCALL(status) (WSTOPSIG(status) == (SIGTRAP | 0x80))

// struct for passing arguments from main to child_main
struct child_args {
    char *dir;
    pid_t uid;
};

// table to keep track of guest processes.
// table implemented cheap and easy as an array;
// given the whole point of this table is to limit
// the number of guest processes to 3, this is alright,
// if a little inflexible designwise.
struct {
    pid_t pid;
    bool is_exit_expected;
    bool is_blocked;
} pinfo[TABLE_SIZE] = {{0, false, false}, {0, false, false}, {0, false, false}};

// function prototypes
int handle_death(pid_t guest_pid, pid_t child_pid);
int handle_PEVENT(pid_t guest_pid);
int handle_syscall(pid_t guest_pid);
int handle_signal_delivery(pid_t guest_pid, int status);
int child_main(void *arg_struct);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <path> <uid>\n", argv[0]);
        return 1;
    }

    // allocate memory for child process
    char *stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        perror("malloc() for child process stack failed!\n");
        return 1;
    }

    // populate child process arguments
    char *dir = argv[1];
    int uid = atoi(argv[2]);
    if (uid == 0) {
        perror("atoi() for uid argument failed!\n");
        return 1;
    }
    struct child_args args = {dir, uid};

    // clone with CLONE_NEWPID to place process in PID namespace
    pid_t child_pid =
        clone(child_main, stack + STACK_SIZE, CLONE_NEWPID, &args);
    if (child_pid == -1) {
        perror("clone() for child process failed!\n");
        return 1;
    }

    // save child process's PID
    pinfo[0].pid = child_pid;

    // wait for OS to create child process
    sleep(1);

    int status;

    // wait for child process's PTRACE_TRACEME
    if (waitpid(child_pid, &status, 0) == -1) {
        perror("waitpid() for PTRACE_TRACEME in parent failed!\n");
        return 1;
    }

    // set options; TRACECLONE, TRACEFORK, and TRACEVFORK allow for easy
    // following of guest processes; EXITKILL kills all tracee threads if the
    // tracer dies; TRACESYSGOOD sets WSTOPSIG(status) to SIGTRAP | 0x80 for
    // syscall-stops instead of just SIGTRAP, which makes it miles easier to
    // tell the stops apart. also note this doesn't resume the tracee, so no
    // need for a waitpid().
    if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1) {
        perror("ptrace() with PTRACE_SETOPTIONS in parent failed!\n");
        return 1;
    }

    // kick things off
    if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1) {
        perror("ptrace() with PTRACE_SYSCALL initialization in sandboxer "
               "failed!\n");
        return 1;
    }

    // loop to snag ptrace-stops
    while (1) {
        // wait, not waitpid, to catch all possible children
        pid_t guest_pid = wait(&status);
        if (guest_pid == -1) {
            perror("wait() for ptrace-stop in sandboxer failed!\n");
            return 1;
        }

        // differentiating between ptrace-stops:
        // has the process died? (oh no...)
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (handle_death(guest_pid, child_pid))
                break;
            continue;
        }

        // otherwise it's a stop
        if (WIFSTOPPED(status)) {
            // is it probably not a signal-delivery-stop?
            if (WSTOPSIG(status) == SIGTRAP) {
                // is it a PTRACE_EVENT-stop?
                if (WIFCLONE(status) || WIFFORK(status) || WIFVFORK(status)) {
                    if (handle_PEVENT(guest_pid))
                        return 1;
                    continue;
                }
            }

            // is it a syscall-stop?
            if (WIFSYSCALL(status)) {
                if (handle_syscall(guest_pid))
                    return 1;
                continue;
            }

            // otherwise, it's probably a signal-delivery-stop
            if (handle_signal_delivery(guest_pid, status))
                return 1;
            continue;
        }

        // otherwise something is amiss
        fprintf(stderr, "wait() returned something unexpected!\n");
        return 1;
    }

    free(stack);

    return 0;
}

// child_main
//
// function executed by the call to clone() in main.
// the clone API allows for only one void * argument,
// so we have to pass a struct and unpack it.

int child_main(void *arg_struct) {
    // send up a ptrace signal to parent process
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace() with PTRACE_TRACEME in child failed!\n");
        return 1;
    }

    // unpack child process arguments
    char *dir = ((struct child_args *)arg_struct)->dir;
    pid_t uid = ((struct child_args *)arg_struct)->uid;

    // change directory to the path of the python script
    if (chdir(dir) == -1) {
        perror("chdir() failed!\n");
        return 1;
    }

    // set the user id to the given uid
    if (setuid(uid) == -1) {
        perror("setuid() failed!\n");
        return 1;
    }

    // execute the python script
    char *args[] = {"python3", "guest.pyc", NULL};
    execvp(args[0], args);
    perror("execvp() failed!\n");
    return 1;
}

// HELPER FUNCTIONS
//
// these handle the different kinds of ptrace-stops in the main loop.

int handle_death(pid_t guest_pid, pid_t child_pid) {
    // if it's the original child, we're done;
    // we'll let PTRACE_O_EXITKILL take care of the rest
    if (guest_pid == child_pid)
        return 1;

    // otherwise, remove the guest from the table
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (pinfo[i].pid == guest_pid) {
            pinfo[i].pid = 0;
            pinfo[i].is_exit_expected = false;
            pinfo[i].is_blocked = false;
            break;
        }
    }

    return 0;
}

int handle_PEVENT(pid_t guest_pid) {
    // we don't as of yet do anything with these, so...

    // restart the tracee
    if (ptrace(PTRACE_SYSCALL, guest_pid, NULL, NULL) == -1) {
        perror("ptrace() with PTRACE_SYSCALL restart in "
               "sandboxer handle_PEVENT failed!\n");
        return 1;
    }
    return 0;
}

int handle_syscall(pid_t guest_pid) {
    // is this a new guest process?
    bool is_new = true;
    bool is_empty_slot = false;
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (pinfo[i].pid == guest_pid)
            is_new = false;
        if (pinfo[i].pid == 0)
            is_empty_slot = true;
    }

    if (is_new) {
        // is there room for a new guest process?
        if (is_empty_slot) {
            // add the new guest process to the table
            for (int i = 0; i < TABLE_SIZE; i++) {
                if (pinfo[i].pid == 0) {
                    pinfo[i].pid = guest_pid;
                    pinfo[i].is_exit_expected = false;
                    pinfo[i].is_blocked = false;
                    break;
                }
            }
        } else {
            // kill the new guest process
            if (kill(guest_pid, SIGKILL) == -1) {
                perror("kill() for new guest process in sandboxer failed!\n");
                return 1;
            }
            return 0;
        }
    }

    // implement syscall filter for connect();
    // gather data and set is_exit_expected flag
    bool is_exit_expected = false;
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (pinfo[i].pid == guest_pid) {
            is_exit_expected = pinfo[i].is_exit_expected;
            pinfo[i].is_exit_expected = !is_exit_expected;
        }
    }
    // is this a syscall-entry-stop or a syscall-exit-stop?
    if (!is_exit_expected) {
        // syscall-entry-stop; block SYSCALL_CONNECT
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, guest_pid, NULL, &regs) == -1) {
            perror("ptrace() with PTRACE_GETREGS in sandboxer handle_syscall "
                   "failed!\n");
            return 1;
        }

        if (regs.orig_rax == SYS_connect) {
            // is it connecting to a socket of the form 127.0.0.*?
            // (this is messy; peek at 2nd argument (rsi), convert in true
            // reckless C fashion to sockaddr_in, and check sin_addr.s_addr,
            // which ends up being in big endian for some weird reason)
            long peek = ptrace(PTRACE_PEEKDATA, guest_pid, regs.rsi, NULL);
            if (peek == -1) {
                perror("ptrace() with PTRACE_PEEKDATA in sandboxer "
                       "handle_syscall failed!\n");
                return 1;
            }
            struct sockaddr_in addr = *(struct sockaddr_in *)&peek;
            in_addr_t s_addr = addr.sin_addr.s_addr;
            if ((s_addr & 0x00FFFFFF) != 0x0000007F) {
                // not of the form 127.0.0.*; so block the syscall
                for (int i = 0; i < TABLE_SIZE; i++) {
                    if (pinfo[i].pid == guest_pid) {
                        pinfo[i].is_blocked = true;
                        break;
                    }
                }
                regs.orig_rax = -1;
                if (ptrace(PTRACE_SETREGS, guest_pid, NULL, &regs) == -1) {
                    perror("ptrace() with PTRACE_SETREGS in sandboxer "
                           "handle_syscall failed!\n");
                    return 1;
                }
            }
        }
    } else {
        // syscall-exit-stop; block SYSCALL_CONNECT if we've set the blocked
        // flag when processing the respective syscall-entry-stop
        for (int i = 0; i < TABLE_SIZE; i++) {
            if (pinfo[i].pid == guest_pid && pinfo[i].is_blocked) {
                pinfo[i].is_blocked = false;
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, guest_pid, NULL, &regs) == -1) {
                    perror("ptrace() with PTRACE_GETREGS in sandboxer "
                           "handle_syscall failed!\n");
                    return 1;
                }
                regs.rax = -EPERM;
                if (ptrace(PTRACE_SETREGS, guest_pid, NULL, &regs) == -1) {
                    perror("ptrace() with PTRACE_SETREGS in sandboxer "
                           "handle_syscall failed!\n");
                    return 1;
                }
                break;
            }
        }
    }

    // restart the tracee
    if (ptrace(PTRACE_SYSCALL, guest_pid, NULL, NULL) == -1) {
        perror("ptrace() with PTRACE_SYSCALL restart in "
               "sandboxer handle_syscall failed!\n");
        return 1;
    }

    return 0;
}

int handle_signal_delivery(pid_t guest_pid, int status) {
    // restart by re-injecting the signal unchanged into the tracee
    if (ptrace(PTRACE_SYSCALL, guest_pid, NULL, WSTOPSIG(status)) == -1) {
        perror("ptrace() with PTRACE_SYSCALL signal injection in "
               "sandboxer handle_signal_delivery failed!\n");
        return 1;
    }

    return 0;
}
