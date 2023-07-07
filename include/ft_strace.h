#ifndef FT_STRACE_H
#define FT_STRACE_H

#include <sys/time.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <elf.h>

#define TNONE 0
#define TINT 1
#define TUINT 2
#define TSTR 3
#define TLSTR 4
#define TPTR 5

typedef struct user_regs_struct32
{
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned int esi;
	unsigned int edi;
	unsigned int ebp;
	unsigned int eax;
	unsigned int xds;
	unsigned int xes;
	unsigned int xfs;
	unsigned int xgs;
	unsigned int orig_eax;
	unsigned int eip;
	unsigned int xcs;
	unsigned int eflags;
	unsigned int esp;
	unsigned int xss;
} t_regs_32;

typedef struct s_syscall
{
	unsigned long code64;
	unsigned long code32;
	char *name;
	int arg[7];
	int ret;
} t_syscall;

typedef struct s_sig
{
	int num;
	char *name;
} t_sig;

typedef struct s_summary
{
	int arch;
	int number_of_calls;
	int error;
	double pourcent_time;
	double seconds;
	long long usecond;
	unsigned long syscall;
	char *name;
	int on;
	struct s_summary *next;
} t_summary;

union regs_union
{
	t_regs_32 regs32;
	struct user_regs_struct regs64;
};

void summary_activate(unsigned long sys, union regs_union regs, int is_64bit);
void print_summary(double time);
void free_summary(void);
void print_read_args(pid_t pid, union regs_union regs, int is_64bit);
void print_syscall_32(unsigned long sys, t_regs_32 regs, int pid);
void print_syscall_64(unsigned long sys, struct user_regs_struct regs, int pid);
double calc_time();
double microseconds_to_seconds(long long microseconds);
long long time_in_microseconds(struct timeval start_time, struct timeval end_time);
int check_summary(unsigned long sys, int error);
t_summary *ft_fill_summary(int nb, int error, int sys, long long time);

void ft_lstadd_back(t_summary **alst, t_summary *new);
double calc_pourcent(double valeur, double total);
char *ft_itoa(unsigned long n, int base);

extern t_summary *g_summary;

static const t_syscall g_syscall[] =
	{
		{0, 3, "read", {TINT, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{1, 4, "write", {TINT, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{2, 5, "open", {TSTR, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{3, 6, "close", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{4, 106, "stat", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{5, 108, "fstat", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{6, 107, "lstat", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{7, 168, "poll", {TPTR, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{8, 19, "lseek", {TINT, TINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{9, 90, "mmap", {TPTR, TUINT, TUINT, TUINT, TUINT, TUINT}, TPTR},
		{10, 125, "mprotect", {TPTR, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{11, 91, "munmap", {TPTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{12, 45, "brk", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TPTR},
		{13, 174, "rt_sigaction", {TINT, TPTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{14, 175, "rt_sigprocmask", {TINT, TPTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{15, 173, "rt_sigreturn", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{16, 54, "ioctl", {TUINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{17, 180, "pread64", {TUINT, TSTR, TUINT, TUINT, TNONE, TNONE}, TINT},
		{18, 181, "pwrite64", {TUINT, TSTR, TUINT, TUINT, TNONE, TNONE}, TINT},
		{19, 145, "readv", {TUINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{20, 146, "writev", {TUINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{21, 33, "access", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{22, 42, "pipe", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{23, 82, "select", {TINT, TPTR, TPTR, TPTR, TPTR, TNONE}, TINT},
		{24, 158, "sched_yield", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{25, 163, "mremap", {TUINT, TUINT, TUINT, TUINT, TUINT, TNONE}, TINT},
		{26, 144, "msync", {TUINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{27, 218, "mincore", {TUINT, TUINT, TSTR, TNONE, TNONE, TNONE}, TINT},
		{28, 219, "madvise", {TUINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{29, -1, "shmget", {TINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{30, -1, "shmat", {TINT, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{31, -1, "shmctl", {TINT, TINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{32, 41, "dup", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{33, 63, "dup2", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{34, 29, "pause", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{35, 162, "nanosleep", {TPTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{36, 105, "getitimer", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{37, 27, "alarm", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{38, 104, "setitimer", {TINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{39, 20, "getpid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{40, 187, "sendfile", {TINT, TINT, TPTR, TUINT, TNONE, TNONE}, TINT},
		{41, 359, "socket", {TINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{42, 362, "connect", {TINT, TPTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{43, -1, "accept", {TINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{44, 369, "sendto", {TINT, TPTR, TUINT, TUINT, TPTR, TPTR}, TINT},
		{45, 371, "recvfrom", {TINT, TPTR, TUINT, TUINT, TPTR, TPTR}, TINT},
		{46, 370, "sendmsg", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{47, 372, "recvmsg", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{48, 373, "shutdown", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{49, 361, "bind", {TINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{50, 363, "listen", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{51, 367, "getsockname", {TINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{52, 368, "getpeername", {TINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{53, 360, "socketpair", {TINT, TINT, TINT, TPTR, TNONE, TNONE}, TINT},
		{54, 366, "setsockopt", {TINT, TINT, TINT, TSTR, TINT, TNONE}, TINT},
		{55, 365, "getsockopt", {TINT, TINT, TINT, TSTR, TPTR, TNONE}, TINT},
		{56, 120, "clone", {TUINT, TUINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{57, 2, "fork", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{58, 190, "vfork", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{59, 11, "execve", {TSTR, TLSTR, TLSTR, TNONE, TNONE, TNONE}, TINT},
		{60, 1, "exit", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{61, 114, "wait4", {TINT, TPTR, TINT, TPTR, TNONE, TNONE}, TINT},
		{62, 37, "kill", {TUINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{63, 122, "uname", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{64, -1, "semget", {TUINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{65, -1, "semop", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{66, -1, "semctl", {TINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{67, -1, "shmdt", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{68, -1, "msgget", {TUINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{69, -1, "msgsnd", {TINT, TPTR, TUINT, TINT, TNONE, TNONE}, TINT},
		{70, -1, "msgrcv", {TINT, TPTR, TUINT, TINT, TINT, TNONE}, TINT},
		{71, -1, "msgctl", {TINT, TINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{72, 55, "fcntl", {TUINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{73, 143, "flock", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{74, 118, "fsync", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{75, 148, "fdatasync", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{76, 92, "truncate", {TSTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{77, 93, "ftruncate", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{78, 141, "getdents", {TUINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{79, 183, "getcwd", {TSTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{80, 12, "chdir", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{81, 133, "fchdir", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{82, 38, "rename", {TSTR, TSTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{83, 39, "mkdir", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{84, 40, "rmdir", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{85, 8, "creat", {TUINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{86, 9, "link", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{87, 10, "unlink", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{88, 83, "symlink", {TSTR, TSTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{89, 85, "readlink", {TSTR, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{90, 15, "chmod", {TSTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{91, 94, "fchmod", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{92, 182, "chown", {TSTR, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{93, 95, "fchown", {TUINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{94, 16, "lchown", {TSTR, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{95, 60, "umask", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{96, 78, "gettimeofday", {TPTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{97, 76, "getrlimit", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{98, 77, "getrusage", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{99, 116, "sysinfo", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{100, 43, "times", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{101, 26, "ptrace", {TINT, TINT, TUINT, TUINT, TNONE, TNONE}, TINT},
		{102, 24, "getuid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{103, 103, "syslog", {TINT, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{104, 47, "getgid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{105, 23, "setuid", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{106, 46, "setgid", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{107, 49, "geteuid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{108, 50, "getegid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{109, 57, "setpgid", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{110, 64, "getppid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{111, 65, "getpgrp", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{112, 66, "setsid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{113, 70, "setreuid", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{114, 71, "setregid", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{115, 80, "getgroups", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{116, 81, "setgroups", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{117, 164, "setresuid", {TPTR, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{118, 165, "getresuid", {TPTR, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{119, 170, "setresgid", {TUINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{120, 171, "getresgid", {TPTR, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{121, 132, "getpgid", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{122, 138, "setfsuid", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{123, 139, "setfsgid", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{124, 147, "getsid", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{125, 184, "capget", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{126, 185, "capset", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{127, 176, "rt_sigpending", {TPTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{128, 177, "rt_sigtimedwait", {TPTR, TPTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{129, 178, "rt_sigqueueinfo", {TUINT, TINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{130, 179, "rt_sigsuspend", {TPTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{131, 186, "sigaltstack", {TPTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{132, 30, "utime", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{133, 14, "mknod", {TSTR, TINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{134, 86, "uselib", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{135, 136, "personality", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{136, 62, "ustat", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{137, 99, "statfs", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{138, 100, "fstatfs", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{139, 135, "sysfs", {TINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{140, 96, "getpriority", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{141, 97, "setpriority", {TINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{142, 154, "sched_setparam", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{143, 155, "sched_getparam", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{144, 156, "sched_setscheduler", {TUINT, TINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{145, 157, "sched_getscheduler", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{146, 159, "sched_get_priority_max", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{147, 160, "sched_get_priority_min", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{148, 161, "sched_rr_get_interval", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{149, 150, "mlock", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{150, 151, "munlock", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{151, 152, "mlockall", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{152, 153, "munlockall", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{153, 111, "vhangup", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{154, 123, "modify_ldt", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{155, 217, "pivot_root", {TSTR, TSTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{156, 149, "_sysctl", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{157, 172, "prctl", {TINT, TUINT, TUINT, TUINT, TNONE, TNONE}, TINT},
		{158, 384, "arch_prctl", {TPTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{159, 124, "adjtimex", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{160, 75, "setrlimit", {TUINT, TINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{161, 61, "chroot", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{162, 36, "sync", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{163, 51, "acct", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{164, 79, "settimeofday", {TPTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{165, 21, "mount", {TSTR, TSTR, TSTR, TUINT, TPTR, TNONE}, TINT},
		{166, 52, "umount2", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{167, 87, "swapon", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{168, 115, "swapoff", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{169, 88, "reboot", {TINT, TINT, TUINT, TPTR, TNONE, TNONE}, TINT},
		{170, 74, "sethostname", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{171, 121, "setdomainname", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{172, 110, "iopl", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{173, 101, "ioperm", {TUINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{174, 127, "create_module", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{175, 128, "init_module", {TPTR, TUINT, TSTR, TNONE, TNONE, TNONE}, TINT},
		{176, 129, "delete_module", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{177, 130, "get_kernel_syms", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{178, 167, "query_module", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{179, 131, "quotactl", {TUINT, TSTR, TUINT, TPTR, TNONE, TNONE}, TINT},
		{180, 169, "nfsservctl", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{181, 188, "getpmsg", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{182, 189, "putpmsg", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{183, 137, "afs_syscall", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{184, -1, "tuxcall", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{185, -1, "security", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{186, 224, "gettid", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{187, 225, "readahead", {TINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{188, 226, "setxattr", {TSTR, TSTR, TPTR, TUINT, TINT, TNONE}, TINT},
		{189, 227, "lsetxattr", {TSTR, TSTR, TPTR, TUINT, TINT, TNONE}, TINT},
		{190, 228, "fsetxattr", {TINT, TSTR, TPTR, TUINT, TINT, TNONE}, TINT},
		{191, 229, "getxattr", {TSTR, TSTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{192, 230, "lgetxattr", {TSTR, TSTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{193, 231, "fgetxattr", {TINT, TSTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{194, 232, "listxattr", {TSTR, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{195, 233, "llistxattr", {TSTR, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{196, 234, "flistxattr", {TINT, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{197, 235, "removexattr", {TSTR, TSTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{198, 236, "lremovexattr", {TSTR, TSTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{199, 237, "fremovexattr", {TINT, TSTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{200, 238, "tkill", {TUINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{201, 13, "time", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{202, 240, "futex", {TPTR, TINT, TUINT, TPTR, TPTR, TUINT}, TINT},
		{203, 241, "sched_setaffinity", {TUINT, TUINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{204, 242, "sched_getaffinity", {TUINT, TUINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{205, 243, "set_thread_area", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{206, 245, "io_setup", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{207, 246, "io_destroy", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{208, 247, "io_getevents", {TUINT, TUINT, TUINT, TPTR, TNONE, TNONE}, TINT},
		{209, 248, "io_submit", {TUINT, TUINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{210, 249, "io_cancel", {TUINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{211, 244, "get_thread_area", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{212, 253, "lookup_dcookie", {TUINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{213, 254, "epoll_create", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{214, -1, "epoll_ctl_old", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{215, -1, "epoll_wait_old", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{216, 257, "remap_file_pages", {TUINT, TUINT, TUINT, TUINT, TUINT, TNONE}, TINT},
		{217, 220, "getdents64", {TUINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{218, 258, "set_tid_address", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{219, 0, "restart_syscall", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{220, -1, "semtimedop", {TINT, TPTR, TUINT, TPTR, TNONE, TNONE}, TINT},
		{221, 250, "fadvise64", {TINT, TUINT, TUINT, TINT, TNONE, TNONE}, TINT},
		{222, 259, "timer_create", {TUINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{223, 260, "timer_settime", {TUINT, TINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{224, 261, "timer_gettime", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{225, 262, "timer_getoverrun", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{226, 263, "timer_delete", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{227, 264, "clock_settime", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{228, 265, "clock_gettime", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{229, 266, "clock_getres", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{230, 267, "clock_nanosleep", {TUINT, TINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{231, 252, "exit_group", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{232, 256, "epoll_wait", {TINT, TPTR, TINT, TINT, TNONE, TNONE}, TINT},
		{233, 255, "epoll_ctl", {TINT, TINT, TINT, TPTR, TNONE, TNONE}, TINT},
		{234, 270, "tgkill", {TUINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{235, 271, "utimes", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{236, 273, "vserver", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{237, 274, "mbind", {TUINT, TUINT, TUINT, TPTR, TUINT, TUINT}, TINT},
		{238, 276, "set_mempolicy", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{239, 275, "get_mempolicy", {TPTR, TPTR, TUINT, TUINT, TUINT, TNONE}, TINT},
		{240, 277, "mq_open", {TSTR, TINT, TUINT, TPTR, TNONE, TNONE}, TINT},
		{241, 278, "mq_unlink", {TSTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{242, 279, "mq_timedsend", {TUINT, TSTR, TUINT, TUINT, TPTR, TNONE}, TINT},
		{243, 280, "mq_timedreceive", {TSTR, TUINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{244, 281, "mq_notify", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{245, 282, "mq_getsetattr", {TPTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{246, 283, "kexec_load", {TUINT, TUINT, TPTR, TUINT, TNONE, TNONE}, TINT},
		{247, 284, "waitid", {TINT, TUINT, TPTR, TINT, TPTR, TNONE}, TINT},
		{248, 286, "add_key", {TSTR, TSTR, TPTR, TUINT, TNONE, TNONE}, TINT},
		{249, 287, "request_key", {TSTR, TSTR, TSTR, TUINT, TNONE, TNONE}, TINT},
		{250, 288, "keyctl", {TINT, TUINT, TUINT, TUINT, TUINT, TNONE}, TINT},
		{251, 289, "ioprio_set", {TINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{252, 290, "ioprio_get", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{253, 291, "inotify_init", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{254, 292, "inotify_add_watch", {TINT, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{255, 293, "inotify_rm_watch", {TINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{256, 294, "migrate_pages", {TUINT, TUINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{257, 295, "openat", {TINT, TSTR, TINT, TINT, TNONE, TNONE}, TINT},
		{258, 296, "mkdirat", {TINT, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{259, 297, "mknodat", {TINT, TSTR, TINT, TUINT, TNONE, TNONE}, TINT},
		{260, 298, "fchownat", {TINT, TSTR, TUINT, TUINT, TINT, TNONE}, TINT},
		{261, 299, "futimesat", {TINT, TSTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{262, 300, "newfstatat", {TINT, TSTR, TPTR, TINT, TNONE, TNONE}, TINT},
		{263, 301, "unlinkat", {TINT, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{264, 302, "renameat", {TINT, TSTR, TINT, TSTR, TNONE, TNONE}, TINT},
		{265, 303, "linkat", {TINT, TSTR, TINT, TSTR, TINT, TNONE}, TINT},
		{266, 304, "symlinkat", {TSTR, TINT, TSTR, TNONE, TNONE, TNONE}, TINT},
		{267, 305, "readlinkat", {TINT, TSTR, TSTR, TINT, TNONE, TNONE}, TINT},
		{268, 306, "fchmodat", {TINT, TSTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{269, 307, "faccessat", {TINT, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{270, 308, "pselect6", {TINT, TSTR, TSTR, TSTR, TSTR, TSTR}, TINT},
		{271, 309, "ppoll", {TPTR, TUINT, TPTR, TPTR, TUINT, TNONE}, TINT},
		{272, 310, "unshare", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{273, 311, "set_robust_list", {TPTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{274, 312, "get_robust_list", {TINT, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{275, 313, "splice", {TINT, TPTR, TINT, TPTR, TUINT, TUINT}, TINT},
		{276, 315, "tee", {TINT, TINT, TUINT, TUINT, TNONE, TNONE}, TINT},
		{277, 314, "sync_file_range", {TUINT, TUINT, TUINT, TUINT, TNONE, TNONE}, TINT},
		{278, 316, "vmsplice", {TINT, TPTR, TUINT, TUINT, TNONE, TNONE}, TINT},
		{279, 317, "move_pages", {TUINT, TUINT, TPTR, TPTR, TPTR, TINT}, TINT},
		{280, 320, "utimensat", {TINT, TPTR, TPTR, TINT, TNONE, TNONE}, TINT},
		{281, 319, "epoll_pwait", {TINT, TPTR, TINT, TINT, TPTR, TUINT}, TINT},
		{282, 321, "signalfd", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{283, 322, "timerfd_create", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{284, 323, "eventfd", {TUINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{285, 324, "fallocate", {TUINT, TUINT, TUINT, TUINT, TNONE, TNONE}, TINT},
		{286, 325, "timerfd_settime", {TINT, TINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{287, 326, "timerfd_gettime", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{288, 364, "accept4", {TINT, TPTR, TPTR, TINT, TNONE, TNONE}, TINT},
		{289, 327, "signalfd4", {TINT, TPTR, TUINT, TINT, TNONE, TNONE}, TINT},
		{290, 328, "eventfd2", {TUINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{291, 329, "epoll_create1", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{292, 330, "dup3", {TUINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{293, 331, "pipe2", {TPTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{294, 332, "inotify_init1", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{295, 333, "preadv", {TUINT, TPTR, TUINT, TUINT, TUINT, TNONE}, TINT},
		{296, 334, "pwritev", {TUINT, TPTR, TUINT, TUINT, TUINT, TNONE}, TINT},
		{297, 335, "rt_tgsigqueueinfo", {TUINT, TUINT, TINT, TPTR, TNONE, TNONE}, TINT},
		{298, 336, "perf_event_open", {TPTR, TUINT, TINT, TINT, TUINT, TNONE}, TINT},
		{299, 337, "recvmmsg", {TINT, TPTR, TUINT, TUINT, TPTR, TNONE}, TINT},
		{300, 338, "fanotify_init", {TUINT, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{301, 339, "fanotify_mark", {TINT, TINT, TUINT, TINT, TINT, TNONE}, TINT},
		{302, 340, "prlimit64", {TUINT, TUINT, TPTR, TPTR, TNONE, TNONE}, TINT},
		{303, 341, "name_to_handle_at", {TINT, TSTR, TPTR, TPTR, TINT, TNONE}, TINT},
		{304, 342, "open_by_handle_at", {TINT, TSTR, TPTR, TPTR, TINT, TNONE}, TINT},
		{305, 343, "clock_adjtime", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{306, 344, "syncfs", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{307, 345, "sendmmsg", {TINT, TPTR, TUINT, TUINT, TNONE, TNONE}, TINT},
		{308, 346, "setns", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{309, 318, "getcpu", {TPTR, TPTR, TPTR, TNONE, TNONE, TNONE}, TINT},
		{310, 347, "process_vm_readv", {TUINT, TPTR, TUINT, TPTR, TUINT, TUINT}, TINT},
		{311, 348, "process_vm_writev", {TUINT, TPTR, TUINT, TPTR, TUINT, TUINT}, TINT},
		{312, 349, "kcmp", {TUINT, TUINT, TINT, TUINT, TUINT, TNONE}, TINT},
		{313, 350, "finit_module", {TINT, TSTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{314, 351, "sched_setattr", {TUINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{315, 352, "sched_getattr", {TUINT, TPTR, TUINT, TUINT, TNONE, TNONE}, TINT},
		{316, 353, "renameat2", {TINT, TSTR, TINT, TSTR, TUINT, TNONE}, TINT},
		{317, 354, "seccomp", {TUINT, TUINT, TSTR, TNONE, TNONE, TNONE}, TINT},
		{318, 355, "getrandom", {TSTR, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{319, 356, "memfd", {TSTR, TUINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{320, -1, "kexec", {TINT, TINT, TUINT, TSTR, TUINT, TNONE}, TINT},
		{321, 357, "bpf", {TINT, TPTR, TUINT, TNONE, TNONE, TNONE}, TINT},
		{322, 358, "execveat", {TINT, TSTR, TLSTR, TLSTR, TINT, TNONE}, TINT},
		{323, 374, "userfaultfd", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{324, 375, "membarrier", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{325, 376, "mlock2", {TUINT, TUINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{326, 377, "copy_file_range", {TINT, TPTR, TINT, TPTR, TUINT, TUINT}, TINT},
		{327, 378, "preadv2", {TUINT, TPTR, TUINT, TUINT, TUINT, TINT}, TINT},
		{328, 379, "pwritev2", {TUINT, TPTR, TUINT, TUINT, TUINT, TINT}, TINT},
		{329, 380, "pkey_mprotect", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{330, 381, "pkey_alloc", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{331, 382, "pkey_free", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{332, 383, "statx", {TUINT, TSTR, TUINT, TUINT, TPTR, TNONE}, TINT},
		{333, -1, "io_pgetevents", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{334, -1, "rseq", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{335, -1, "pkey_mprotect", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 7, "waitpid", {TINT, TPTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{-1, 17, "break", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 18, "oldstat", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 22, "umount", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 25, "stime", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 28, "oldfstat", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 31, "stty", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 32, "gtty", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 34, "nice", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 35, "ftime", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 44, "prof", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 48, "signal", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 53, "lock", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 56, "mpx", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 58, "ulimit", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 59, "oldolduname", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 67, "sigaction", {TINT, TPTR, TINT, TNONE, TNONE, TNONE}, TINT},
		{-1, 68, "sgetmask", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 69, "ssetmask", {TINT, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 72, "sigsuspend", {TINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{-1, 74, "sigpending", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 84, "oldlstat", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 89, "readdir", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 98, "profil", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 102, "socketcall", {TINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 109, "olduname", {TPTR, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 112, "idle", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 113, "vm86old", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 117, "ipc", {TUINT, TINT, TUINT, TUINT, TPTR, TINT}, TINT},
		{-1, 119, "sigreturn", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 126, "sigprocmask", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 134, "bdflush", {TINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 140, "_llseek", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 142, "_newselect", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 166, "vm86", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 191, "ugetrlimit", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 192, "mmap2", {TPTR, TUINT, TINT, TINT, TINT, TINT}, TPTR},
		{-1, 193, "truncate64", {TSTR, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 194, "ftruncate64", {TUINT, TINT, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 195, "stat64", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 196, "lstat64", {TSTR, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 197, "fstat64", {TUINT, TPTR, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 198, "lchown32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 199, "getuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 200, "getgid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 201, "geteuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 202, "getegid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 203, "setreuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 204, "setregid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 205, "getgroups32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 206, "setgroups32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 207, "fchown32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 208, "setresuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 209, "getresuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 210, "setresgid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 211, "getresgid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 212, "chown32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 213, "setuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 214, "setgid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 215, "setfsuid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 216, "setsgid32", {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TINT},
		{-1, 221, "fcntl64", {TUINT, TUINT, TUINT, TNONE, TNONE, TNONE}, TINT},
		{-1, 239, "sendfile64", {TINT, TINT, TPTR, TUINT, TNONE, TNONE}, TINT},
		{-1, 268, "statfs64", {TSTR, TUINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{-1, 269, "fstatfs64", {TUINT, TUINT, TPTR, TNONE, TNONE, TNONE}, TINT},
		{-1, 272, "fadvise64_64", {TINT, TINT, TINT, TNONE, TNONE, TNONE}, TINT},
		{-1, -1, NULL, {TNONE, TNONE, TNONE, TNONE, TNONE, TNONE}, TNONE}};

static const t_sig g_sig[] =
	{
		{1, "SIGHUP"},
		{2, "SIGINT"},
		{3, "SIGQUIT"},
		{4, "SIGILL"},
		{5, "SIGTRAP"},
		{6, "SIGABRT"},
		{7, "SIGBUS"},
		{8, "SIGFPE"},
		{9, "SIGKILL"},
		{10, "SIGUSR1"},
		{11, "SIGSEGV"},
		{12, "SIGUSR2"},
		{13, "SIGPIPE"},
		{14, "SIGALRM"},
		{15, "SIGTERM"},
		{16, "SIGSTKFLT"},
		{17, "SIGCHLD"},
		{18, "SIGCONT"},
		{19, "SIGSTOP"},
		{20, "SIGTSTP"},
		{21, "SIGTTIN"},
		{22, "SIGTTOU"},
		{23, "SIGURG"},
		{24, "SIGXCPU"},
		{25, "SIGXFSZ"},
		{26, "SIGVTALRM"},
		{27, "SIGPROF"},
		{28, "SIGWINCH"},
		{29, "SIGIO"},
		{30, "SIGPWR"},
		{31, "SIGSYS"},
		{34, "SIGRTMIN"},
		{35, "SIGRTMIN+1"},
		{36, "SIGRTMIN+2"},
		{37, "SIGRTMIN+3"},
		{38, "SIGRTMIN+4"},
		{39, "SIGRTMIN+5"},
		{40, "SIGRTMIN+6"},
		{41, "SIGRTMIN+7"},
		{42, "SIGRTMIN+8"},
		{43, "SIGRTMIN+9"},
		{44, "SIGRTMIN+10"},
		{45, "SIGRTMIN+11"},
		{46, "SIGRTMIN+12"},
		{47, "SIGRTMIN+13"},
		{48, "SIGRTMIN+14"},
		{49, "SIGRTMIN+15"},
		{50, "SIGRTMAX-14"},
		{51, "SIGRTMAX-13"},
		{52, "SIGRTMAX-12"},
		{53, "SIGRTMAX-11"},
		{54, "SIGRTMAX-10"},
		{55, "SIGRTMAX-9"},
		{56, "SIGRTMAX-8"},
		{57, "SIGRTMAX-7"},
		{58, "SIGRTMAX-6"},
		{59, "SIGRTMAX-5"},
		{60, "SIGRTMAX-4"},
		{61, "SIGRTMAX-3"},
		{62, "SIGRTMAX-2"},
		{63, "SIGRTMAX-1"},
		{64, "SIGRTMAX"},
		{65, NULL}};

#endif