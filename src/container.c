#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <mntent.h>

#include <sys/capability.h>

#define MNT_INVERT (1 << 1)

char *progname;

static const char *mountflag_names[] = {
	"ro",          "rw",
	"noatime",     "atime",
	"nodev",       "dev",
	"nodiratime",  "diratime",
	"noexec",      "exec",
	"nosuid",      "suid",
	"sync",        "async",
	"relatime",    "norelatime",
	"strictatime", "nostrictatime"
	"dirsync",     "nodirsync",
	"lazytime",    "nolazytime",
	"mand",        "nomand",
	"silent",      "loud",
	"defaults",    "nodefaults",
	"auto",        "noauto",
	"rec",
	"bind",
	NULL
};

#define E(x) { x, 0 }, { x, MNT_INVERT }

static struct _mountflag_values {
	unsigned long id;
	unsigned long mask;
} mountflag_values[] = {
	E(MS_RDONLY),
	E(MS_NOATIME),
	E(MS_NODEV),
	E(MS_NODIRATIME),
	E(MS_NOEXEC),
	E(MS_NOSUID),
	E(MS_SYNCHRONOUS),
	E(MS_RELATIME),
	E(MS_STRICTATIME),
	E(MS_DIRSYNC),
	E(MS_LAZYTIME),
	E(MS_MANDLOCK),
	E(MS_SILENT),
	E(0),
	E(0),
	{ MS_REC,  0 },
	{ MS_BIND, 0 },
};

#undef E

static inline void
set_progname(char *name)
{
	char *p;

	p        = strrchr(name, '/');
	progname = (p ? p + 1 : name);
}

static inline void __attribute__((noreturn))
print_version_and_exit(void)
{
	printf("%s v1\n", progname);
	exit(EXIT_SUCCESS);
}

static void __attribute__((noreturn))
usage(int code)
{
	fprintf(stderr, 
		"Usage: %s [options] [--] newroot command [arguments...]\n"
		"\n"
		"Options:\n"
		" -u, --remap-uid=UID   exposes the mapping of user IDs\n"
		" -g, --remap-gid=GID   exposes the mapping of group IDs\n"
		" -h, --help            display this help and exit\n"
		" -V, --version         output version information and exit\n"
		"\n", progname);
	exit(code);
}

static void
map_id(const char *file, uint64_t from, uint64_t to)
{
	int fd;

	fd = open(file, O_WRONLY);
	if (fd < 0)
		 error(EXIT_FAILURE, errno, "cannot open %s", file);

	if (dprintf(fd, "%lu %lu 1\n", from, to) < 0)
		printf("unable to write to %s\n", file);

	close(fd);
}

static void
setgroups_control(const char *value)
{
	FILE *fd;
	if ((fd = fopen("/proc/self/setgroups", "w")) == NULL)
		error(EXIT_FAILURE, errno, "fopen: /proc/self/setgroups");
	fprintf(fd, "%s", value);
	fclose(fd);
}

static struct mntent *
parse_mntent(char *s)
{
	struct mntent *m = calloc(1, sizeof(struct mntent));

	if (!m)
		error(EXIT_FAILURE, errno, "calloc");

	if (sscanf(s, "%ms %ms %ms %ms %*d %*d", &m->mnt_fsname, &m->mnt_dir, &m->mnt_type, &m->mnt_opts) != 4)
		error(EXIT_FAILURE, 0, "unable to parse mountspec: %s", s);

	return m;
}

static void
free_mntent(struct mntent *ent)
{
	free(ent->mnt_fsname);
	free(ent->mnt_dir);
	free(ent->mnt_type);
	free(ent->mnt_opts);
	free(ent);
}

static unsigned long
parse_mountopts(const char *opts)
{
	char *s, *subopts, *value;
	unsigned long flags = 0;
	int i;

	s = subopts = strdup(opts);

	while (*subopts != '\0') {
		if ((i = getsubopt(&subopts, (char **) mountflag_names, &value)) < 0)
			error(EXIT_FAILURE, 0, "unknown mount option: %s", value);

		if (mountflag_values[i].mask & MNT_INVERT)
			flags &= ~mountflag_values[i].id;
		else
			flags |= mountflag_values[i].id;
	}

	free(s);
	return flags;
}

int
main(int argc, char **argv)
{
	int c;
	cap_t caps = 0;
	uint64_t uid = 0;
	uint64_t gid = 0;
	char *newroot;

	struct mntent **mounts = NULL;
	size_t i, n_mounts = 0;

	const struct option long_opts[] = {
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ "caps",    required_argument, NULL, 'c' },
		{ "mount",   required_argument, NULL, 'm' },
		{ "uid",     required_argument, NULL, 'u' },
		{ "gid",     required_argument, NULL, 'g' },
		{ NULL, 0, NULL, 0 }
	};

	uid_t real_euid = geteuid();
	gid_t real_egid = getegid();

	set_progname(argv[0]);

	while ((c = getopt_long(argc, argv, "Vhu:g:c:m:", long_opts, NULL)) != EOF) {
		switch (c) {
			case 'h':
				usage(EXIT_SUCCESS);
				break;
			case 'u':
				uid = strtoul(optarg, NULL, 10);
				break;
			case 'g':
				gid = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				errno = 0;
				caps = cap_from_text(optarg);
				if (errno != 0)
					error(EXIT_FAILURE, errno, "cap_from_text");
				break;
			case 'm':
				mounts = realloc(mounts, n_mounts + 1);
				mounts[n_mounts++] = parse_mntent(optarg);
				break;
			case 'V':
				print_version_and_exit();
				break;
			case '?':
				usage(EXIT_FAILURE);
		}
	}

	if (argc == optind)
		error(EXIT_FAILURE, 0, "New root directory required");

	newroot = argv[optind++];

	if (access(newroot, R_OK|X_OK) < 0)
		error(EXIT_FAILURE, errno, "access: %s", newroot);

	if (argc == optind)
		error(EXIT_FAILURE, 0, "More arguments required");

	if (unshare(CLONE_NEWUSER|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWNS|CLONE_NEWPID) < 0)
		error(EXIT_FAILURE, errno, "unshare1");

	pid_t pid = fork();
	if (pid < 0)
		error(EXIT_FAILURE, errno, "fork");

	if (pid > 0) {
		int status;

		for (i = 0; i < n_mounts; i++)
			free_mntent(mounts[i]);
		if (mounts)
			free(mounts);

		if (waitpid(pid, &status, 0) < 0)
			error(EXIT_FAILURE, errno, "waitpid");

		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			kill(getpid(), WTERMSIG(status));

		return EXIT_SUCCESS;
	}

	/* since Linux 3.19 unprivileged writing of /proc/self/gid_map
	 * has s been disabled unless /proc/self/setgroups is written
	 * first to permanently disable the ability to call setgroups
	 * in that user namespace.
	 */
	setgroups_control("deny");

	map_id("/proc/self/uid_map", uid, real_euid);
	map_id("/proc/self/gid_map", gid, real_egid);

	for (i = 0; i < n_mounts; i++) {
		char mpoint[MAXPATHLEN];
		unsigned long mflags = parse_mountopts(mounts[i]->mnt_opts);

		if ((strlen(newroot) + strlen(mounts[i]->mnt_dir)) >= MAXPATHLEN)
			error(EXIT_FAILURE, 0, "mountpoint name too long");

		sprintf(mpoint, "%s%s", newroot, mounts[i]->mnt_dir);

		if (access(mpoint, F_OK) < 0) {
			fprintf(stderr, "WARNING: mountpoint not found in the container: %s\n", mounts[i]->mnt_dir);
			free_mntent(mounts[i]);
			continue;
		}

		if (mount(mounts[i]->mnt_fsname, mpoint, mounts[i]->mnt_type, mflags, NULL) < 0)
			error(EXIT_FAILURE, errno, "mount");

		free_mntent(mounts[i]);
	}
	if (mounts)
		free(mounts);

	if (chroot(newroot) < 0)
		error(EXIT_FAILURE, errno, "chroot");

	if (chdir("/") < 0)
		error(EXIT_FAILURE, errno, "chdir");

	if (caps) {
		if (cap_set_proc(caps) < 0)
			error(EXIT_FAILURE, errno, "cap_set_proc");

		if (cap_free(caps) < 0)
			error(EXIT_FAILURE, errno, "cap_free");
	}

	if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		error(EXIT_FAILURE, errno, "prctl(PR_SET_NO_NEW_PRIVS)");

	execvp(argv[optind], argv + optind);
	error(EXIT_FAILURE, errno, "execvp");

	return EXIT_FAILURE;
}
