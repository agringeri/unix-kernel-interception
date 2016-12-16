// Anthony Gringeri
// acgringeri

#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "processinfo_user.h"

#define __NR_cs3013_syscall2 356

long test_call(struct processinfo *info) {
        return (long) syscall(__NR_cs3013_syscall2, info);
}

int main () {
	int process1;
	int process2;
	int status; // Variable that holds state of process

	if ((process1 = fork()) < 0) {
		printf("Process fork failed.\n");
	} else if (process1 == 0) {
		// child
		struct processinfo my_info_1;
		if (test_call(&my_info_1) == 0) {
			printf("\nCHILD PROCESS:\n");
			printf("cs3013_syscall2 returned: %ld\n", test_call(&my_info_1));
			printf("State: %li \n", my_info_1.state);
			printf("PID: %i \n", my_info_1.pid);
			printf("Parent PID: %i \n", my_info_1.parent_pid);
			printf("Youngest Child PID: %i \n", my_info_1.youngest_child);
			printf("Younger Sibling PID: %i \n", my_info_1.younger_sibling);
			printf("Older Sibling PID: %i \n", my_info_1.older_sibling);
			printf("UID: %i \n", my_info_1.uid);
			printf("Start time (nanoseconds): %lli \n", my_info_1.start_time);
			printf("CPU time in user mode: %lli \n", my_info_1.user_time);
			printf("CPU time in system mode: %lli \n", my_info_1.sys_time);
			printf("User time of children: %lli \n", my_info_1.cutime);
			printf("System time of children: %lli \n", my_info_1.cstime);
		} 
		return 0;
	} else {
		// parent
		if ((process2 = fork()) < 0) {
			printf("Process fork failed.\n");
		} else if (process2 == 0) {
			// child
			struct processinfo my_info_2;
			if (test_call(&my_info_2) == 0) {
				printf("\nCHILD PROCESS:\n");
				printf("cs3013_syscall2 returned: %ld\n", test_call(&my_info_2));
				printf("State: %li \n", my_info_2.state);
				printf("PID: %i \n", my_info_2.pid);
				printf("Parent PID: %i \n", my_info_2.parent_pid);
				printf("Youngest Child PID: %i \n", my_info_2.youngest_child);
				printf("Younger Sibling PID: %i \n", my_info_2.younger_sibling);
				printf("Older Sibling PID: %i \n", my_info_2.older_sibling);
				printf("UID: %i \n", my_info_2.uid);
				printf("Start time (nanoseconds): %lli \n", my_info_2.start_time);
				printf("CPU time in user mode: %lli \n", my_info_2.user_time);
				printf("CPU time in system mode: %lli \n", my_info_2.sys_time);
				printf("User time of children: %lli \n", my_info_2.cutime);
				printf("System time of children: %lli \n", my_info_2.cstime);
		} 
		return 0;
	} else {
		// parent
		struct processinfo my_info_3;
		if (test_call(&my_info_3) == 0) {
			printf("\nPARENT PROCESS:\n");
			printf("cs3013_syscall2 returned: %ld\n", test_call(&my_info_3));
			printf("State: %li \n", my_info_3.state);
			printf("PID: %i \n", my_info_3.pid);
			printf("Parent PID: %i \n", my_info_3.parent_pid);
			printf("Youngest Child PID: %i \n", my_info_3.youngest_child);
			printf("Younger Sibling PID: %i \n", my_info_3.younger_sibling);
			printf("Older Sibling PID: %i \n", my_info_3.older_sibling);
			printf("UID: %i \n", my_info_3.uid);
			printf("Start time (nanoseconds): %lli \n", my_info_3.start_time);
			printf("CPU time in user mode: %lli \n", my_info_3.user_time);
			printf("CPU time in system mode: %lli \n", my_info_3.sys_time);
			printf("User time of children: %lli \n", my_info_3.cutime);
			printf("System time of children: %lli \n", my_info_3.cstime);
		}

		waitpid(process1, &status, 0); // wait for process to complete
		waitpid(process2, &status, 0); // wait for porcess to complete

		struct processinfo my_info_4;
		if (test_call(&my_info_4) == 0) {
			printf("\nPARENT PROCESS:\n");
			printf("cs3013_syscall2 returned: %ld\n", test_call(&my_info_4));
			printf("State: %li \n", my_info_4.state);
			printf("PID: %i \n", my_info_4.pid);
			printf("Parent PID: %i \n", my_info_4.parent_pid);
			printf("Youngest Child PID: %i \n", my_info_4.youngest_child);
			printf("Younger Sibling PID: %i \n", my_info_4.younger_sibling);
			printf("Older Sibling PID: %i \n", my_info_4.older_sibling);
			printf("UID: %i \n", my_info_4.uid);
			printf("Start time (nanoseconds): %lli \n", my_info_4.start_time);
			printf("CPU time in user mode: %lli \n", my_info_4.user_time);
			printf("CPU time in system mode: %lli \n", my_info_4.sys_time);
			printf("User time of children: %lli \n", my_info_4.cutime);
			printf("System time of children: %lli \n", my_info_4.cstime);
		}
	}
	}
	return 0; // Done
}


