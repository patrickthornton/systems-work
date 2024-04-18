#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstdio>


// these two constants are used by builtin functions to simulate the statuses of forked processes
#define STATUS_SUCCESS 0	// WIFEXITED(0) == 1 and WEXITSTATUS(0) == 0,
							// so it describes a process that exited via _exit(EXIT_SUCCESS)
#define STATUS_FAILURE 256 	// WIFEXITED(256) == 1 and WEXITSTATUS(256) == 1,
					 		// so it describes a process that exited via _exit(EXIT_FAILURE)


// struct command
//    Data structure describing a command.

struct command 
{
    std::vector<std::string> args;	// argument vector; args[0] is the name of the command
    pid_t pid = -1;      			// process ID running this command, -1 if none

    command* next = nullptr;
    command* prev = nullptr;		// command line represented as a doubly linked list

    int op = TYPE_SEQUENCE; 		// operator following this command;
                    				// always TYPE_SEQUENCE or TYPE_BACKGROUND for last in list
	
	int pfd[2] = {0, 0};			// if op == TYPE_PIPE, the parts of the pipe are stored here;
									// pfd[0] and pfd[1] are the read and write ends of the pipe; 0 if N/A

	int redirs[3] = {0, 0, 0};		// store file descriptors of any redirections of STDIN/STDOUT/STDERR; 0 if N/A
									// redir[0], redir[1], and redir[2] are redirections of STDIN, STDOUT, and STDERR
	
    void run();						// method to execute this command
};


// COMMAND EXECUTION

// command::run()
//    Creates a single child process running the command in `this`, and
//    sets `this->pid` to the pid of the child process.
//
//    If a child process cannot be created, this function should call
//    `_exit(EXIT_FAILURE)` (that is, `_exit(1)`) to exit the containing
//    shell or subshell. If this function returns to its caller,
//    `this->pid > 0` must always hold.
//
//    Note that this function must return to its caller *only* in the parent
//    process. The code that runs in the child process must `execvp` and/or
//    `_exit`.
//
//    PART 1: Fork a child process and run the command using `execvp`.
//       This will require creating a vector of `char*` arguments using
//       `this->args[N].c_str()`. Note that the last element of the vector
//       must be a `nullptr`.
//    PART 4: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PART 7: Handle redirections.

void command::run() 
{
    assert(this->pid == -1);
    assert(this->args.size() > 0);

	bool pipe_in = (this->prev && this->prev->op == TYPE_PIPE);
	bool pipe_out = (this->op == TYPE_PIPE);
	if (pipe_out && pipe(this->pfd) == -1)
		_exit(EXIT_FAILURE);

	// fork
	pid_t child_pid = fork();
	if (child_pid == -1)
		_exit(EXIT_FAILURE);

	// parent process: close pipes and return immediately
	if (child_pid)
	{
		if (pipe_in)
			close(this->prev->pfd[0]);
		if (pipe_out)
			close(this->pfd[1]);
		this->pid = child_pid;
		return;
	}

	// child process: if there's a pipe in, replace STDIN with it
	if (pipe_in)
	{
		dup2(this->prev->pfd[0], STDIN_FILENO);
		close(this->prev->pfd[0]);
	}
	// if there's a | next, replace STDOUT with the newly made pipe's write end
	if (pipe_out)
	{
		dup2(this->pfd[1], STDOUT_FILENO);
		close(this->pfd[0]);
		close(this->pfd[1]);
	}

	// check for redirections
	for (int i = 0; i <= 2; ++i)
	{
		// if open() failed, print error and exit
		if (this->redirs[i] == -1)
		{
			fprintf(stderr, "%s\n", strerror(ENOENT)); // "No such file or directory"
			_exit(EXIT_FAILURE);
		}
		if (this->redirs[i])
		{
			dup2(this->redirs[i], i); // being a bit too slick here, maybe; 
									  // STDIN_FILENO is 0, STDOUT_FILENO is 1, and STDERR_FILENO is 2, so this works
			close(this->redirs[i]);
		}
	}

	// execute code
	char* c_args[this->args.size() + 1];
	for (size_t i = 0; i < this->args.size(); ++i)
		c_args[i] = (char*) this->args[i].c_str();
	c_args[this->args.size()] = nullptr;
	execvp(c_args[0], c_args); // should stop here
	_exit(EXIT_FAILURE);
}


// chain_in_background(c)
// 	  Helper function to determine whether this chain of conditionals ends
// 	  in a ; or a &. Returns true if it ends in a &, so the whole chain should
// 	  be backgrounded; returns false if it ends in a ; or we hit the end of the
// 	  command line.

bool chain_in_background(command* c) 
{
    while (c->op != TYPE_SEQUENCE && c->op != TYPE_BACKGROUND)
        c = c->next;
    return c->op == TYPE_BACKGROUND;
}


// run_list(c)
//    Run the command *list* starting at `c`. Initially this just calls
//    `c->run()` and `waitpid`; you’ll extend it to handle command lists,
//    conditionals, and pipelines.
//
//    It is possible, and not too ugly, to handle lists, conditionals,
//    *and* pipelines entirely within `run_list`, but many students choose
//    to introduce `run_conditional` and `run_pipeline` functions that
//    are called by `run_list`. It’s up to you.
//
//    PART 1: Start the single command `c` with `c->run()`,
//        and wait for it to finish using `waitpid`.
//    The remaining parts may require that you change `struct command`
//    (e.g., to track whether a command is in the background)
//    and write code in `command::run` (or in helper functions).
//    PART 2: Introduce a loop to run a list of commands, waiting for each
//       to finish before going on to the next.
//    PART 3: Change the loop to handle conditional chains.
//    PART 4: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PART 5: Change the loop to handle background conditional chains.
//       This may require adding another call to `fork()`!

void run_list(command* c) 
{
    int status;					// space for status information from waitpid
	bool short_circuit = false;	// true if we should skip execution of this command due to conditional logic
	pid_t child_pid = -1;		// process ID of child
	bool fork_check = false; 	// true if we've checked for a & later in the chain, false otherwise
	while (c)
	{	
		// if we haven't checked already, see if this chain ends in a &
		if (!fork_check)
		{
			// if it does, fork
			if (chain_in_background(c))
			{
				child_pid = fork();
				if (child_pid == -1)
					_exit(EXIT_FAILURE);

				// move parent process to after the next &
				if (child_pid)
				{
					while (c->op != TYPE_BACKGROUND)
						c = c->next;
					c = c->next;
					if (!c)
						return;
					continue;
				}
			}
			fork_check = true;
		}		

		// if not short-circuited, run
		if (!short_circuit)
		{
			// internal programs (just 'cd' right now, there could be more)
			if (c->args[0] == "cd")
				status = chdir(c->args[1].c_str()) == 0 ? STATUS_SUCCESS : STATUS_FAILURE;
			// external programs
			else
			{
				c->run();
				// pipelined stuff runs in parallel, so no waiting
				if (c->op != TYPE_PIPE)
					waitpid(c->pid, &status, 0);
			}
		}

		// pipelined stuff has higher precedence than conditionals
		if (c->op != TYPE_PIPE)
			short_circuit = false;

		// setting various flags for next command
		switch (c->op)
		{
			// ; - must check for a background chain after this
			case TYPE_SEQUENCE:
				fork_check = false;
				break;

			// & - must check for a background chain after this
			// for a child process running a background chain, it's time to exit
			case TYPE_BACKGROUND:
				if (!child_pid)
					_exit(0);
				fork_check = false;
				break;

			// && - if this command didn't exit or exited false, short-circuit
			case TYPE_AND:
				if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
					short_circuit = true;
				break;

			// || - if this command exited true, short-circuit
			case TYPE_OR:
				if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
					short_circuit = true;
				break;

			default:
				break;
		}
		c = c->next;
	}
}


// parse_line(s)
//    Parse the command list in `s` and return it. Returns `nullptr` if
//    `s` is empty (only spaces). You’ll extend it to handle more token
//    types.

command* parse_line(const char* s) 
{
    shell_parser parser(s);
	command* ch = nullptr; 	// first command in list (head)
	command* ct = nullptr; 	// last command in list (tail)
    command* c = nullptr;	// current command
	bool redirect = false;	// true if last token was of TYPE_REDIRECT_OP, false otherwise
	std::string redirect_token;	// either <, >, or 2>

    for (auto it = parser.begin(); it != parser.end(); ++it)
		switch (it.type())
		{
			// first two cases add to a command
			case TYPE_NORMAL:
				// if first argument, create new command
				if (!c)
				{
					c = new command;
                	if (ct) 
					{
                    	ct->next = c;
                    	c->prev = ct;
                	} 
					else 
                    	ch = c;
				}
				// if not following <, >, or 2>, add to arguments
				// otherwise, add to redirects
				if (!redirect)
					c->args.push_back(it.str());
				else
				{
					if (redirect_token == "<")
						c->redirs[0] = open(it.str().c_str(), O_RDONLY);
					else if (redirect_token == ">")
						c->redirs[1] = open(it.str().c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
					else if (redirect_token == "2>")
						c->redirs[2] = open(it.str().c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
					redirect = false;
				}
				break;
			case TYPE_REDIRECT_OP:
				redirect = true;
				redirect_token = it.str();
				break;

			// all other cases end a command
        	case TYPE_SEQUENCE:
        	case TYPE_BACKGROUND:
        	case TYPE_PIPE:
        	case TYPE_AND:
        	case TYPE_OR:
				assert(c);
				ct = c;
				ct->op = it.type();
				c = nullptr;
				break;
			default:
				break;
		}
    return ch;
}


int main(int argc, char* argv[]) 
{
    FILE* command_file = stdin;
    bool quiet = false;

    // Check for `-q` option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) 
	{
        quiet = true;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) 
	{
        command_file = fopen(argv[1], "rb");
        if (!command_file) 
		{
            perror(argv[1]);
            return 1;
        }
    }

    // - Put the shell into the foreground
    // - Ignore the SIGTTOU signal, which is sent when the shell is put back
    //   into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file)) 
	{
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) 
		{
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = false;
        }

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == nullptr) 
		{
            if (ferror(command_file) && errno == EINTR) 
			{
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } 
			else 
			{
                if (ferror(command_file))
                    perror("sh61");
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) 
		{
			if (command* c = parse_line(buf)) 
			{
                run_list(c);

				// free doubly linked list
				command* temp;
				while (c)
				{
					temp = c;
					c = c->next;
					delete temp;
				}
            }
            bufpos = 0;
            needprompt = 1;
        }

        // Reap zombie processes
		while (waitpid(-1, NULL, WNOHANG) > 0);
    }

    return 0;
}
