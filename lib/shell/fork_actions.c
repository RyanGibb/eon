#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <paths.h>
#include <sys/ioctl.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>

typedef void fork_fn(int errors, value v_args);

static void handle_error(int errors, char *msg) {
	dprintf(errors, "%s: %s", msg, strerror(errno));
	_exit(errno);
}

Caml_inline value Val_fork_fn(fork_fn *fn) {
	return caml_copy_nativeint((intnat) fn);
}

static void action_setup_shell(int errors, value v_config) {
	value pty = Field(v_config, 1);

	int fd, masterfd, slavefd;
	const char *ttyname;

	masterfd = Int_val(Field(pty, 0));
	slavefd = Int_val(Field(pty, 1));
	ttyname = String_val(Field(pty, 2));

	if (dup2(slavefd, STDIN_FILENO) == -1)
		handle_error(errors, "action_setup_shell Error switching stdin");
	if (dup2(slavefd, STDOUT_FILENO) == -1)
		handle_error(errors, "action_setup_shell Error switching stdout");
	if (dup2(slavefd, STDERR_FILENO) == -1)
		handle_error(errors, "action_setup_shell Error switching stderr");

	/* Disconnect from the old tty */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd != -1) {
		ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}

	if (setsid() == -1)
		handle_error(errors, "action_setup_shell Error creating session");

	/* Verify that we have successfully disconnected */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd != -1)
		handle_error(errors, "action_setup_shell Failed to disconnect original tty");

	/* Switch to the new tty */
	if (ioctl(slavefd, TIOCSCTTY, NULL) < 0)
		handle_error(errors, "TIOCSCTTY");

	fd = open(ttyname, O_RDWR);
	if (fd == -1)
		dprintf(errors, "action_setup_shell Error opening %s: %s", ttyname, strerror(errno));
	else
		close(fd);

	/* Verify that the tty is now the controller */
	fd = open(_PATH_TTY, O_WRONLY);
	if (fd == -1)
		handle_error(errors, "action_setup_shell Failed to set controlling tty");
	else
		close(fd);
}

CAMLprim value eio_unix_fork_setup_shell(value v_unit) {
	return Val_fork_fn(action_setup_shell);
}
