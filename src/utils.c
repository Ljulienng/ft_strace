#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	pid_t child_pid;
	struct user_regs_struct regs;

	if (argc <= 1)
	{
		fprintf(stderr, "Usage: %s program [args]\n", argv[0]);
		return 1;
	}

	child_pid = fork();

	if (child_pid == -1)
	{
		perror("fork");
		return 1;
	}
	else if (child_pid == 0)
	{
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
		{
			perror("ptrace child");
			return 1;
		}
		execvp(argv[1], &argv[1]);
		perror("execvp");
		return 1;
	}
	else
	{
		wait(NULL); // Wait for the child to stop
		while (1)
		{
			if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1)
			{
				perror("ptrace parent");
				return 1;
			}
			wait(NULL);
			if (ptrace(PTRACE_GETREGSET, child_pid, NULL, &regs) == -1)
			{
				perror("ptrace getregs");
				return 1;
			}
			printf("System call number: %lld\n", regs.orig_rax);
		}
	}

	return 0;
}
