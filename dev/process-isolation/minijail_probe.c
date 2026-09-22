// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	/* A marker on inherited stdout works even when all writes are denied. */
	puts("WORKLOAD_EXECUTED");
	fflush(stdout);
	if (argc == 2 && !strcmp(argv[1], "marker"))
		return 0;
	char value[32] = {0};
	int fd = open("/allowed", O_RDONLY);
	if (fd < 0 || read(fd, value, sizeof(value) - 1) != 8)
		return 10;
	close(fd);
	if (strcmp(value, "allowed\n"))
		return 11;
	fd = open("/allowed", O_WRONLY | O_TRUNC);
	if (fd >= 0 || errno != EACCES)
		return 12;
	/* These files exist in the root. Only Landlock denies their access. */
	fd = open("/denied", O_RDONLY);
	if (fd >= 0 || errno != EACCES)
		return 13;
	fd = open("/created", O_WRONLY | O_CREAT, 0600);
	if (fd >= 0 || errno != EACCES)
		return 14;
	puts("CONFINEMENT_OK read-allowed write-truncate-read-create-denied");
	return 0;
}
