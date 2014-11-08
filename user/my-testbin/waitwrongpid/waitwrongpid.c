/*
 * An example program.
 */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>

int
main()
{
	pid_t pid = fork();
	if (pid == 0) {
		int retval;
		int success = waitpid(2, &retval, 0);
		if (success != 0) {
			printf("wait not successful\n");
		} else if (WEXITSTATUS(retval) != 0) {
			warnx("pid %d: exit %d", pid, WEXITSTATUS(retval));
		}
	}
	return 0;
}
