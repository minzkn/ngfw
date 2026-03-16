#ifndef NGFW_CLI_H
#define NGFW_CLI_H

#include "types.h"
#include "filter.h"
#include "session.h"
#include "ips.h"

typedef enum {
    CLI_CMD_OK,
    CLI_CMD_INVALID,
    CLI_CMD_HELP,
    CLI_CMD_QUIT
} cli_cmd_result_t;

typedef cli_cmd_result_t (*cli_handler_t)(int argc, char **argv, void *context);

typedef struct cli_command {
    const char *name;
    const char *shortcut;
    const char *description;
    const char *usage;
    cli_handler_t handler;
    struct cli_command *children;
} cli_command_t;

typedef struct cli_session {
    int fd;
    bool interactive;
    void *context;
    char buffer[4096];
    u32 buffer_pos;
} cli_session_t;

typedef struct cli {
    cli_command_t *commands;
    void *context;
    cli_session_t **sessions;
    u32 session_count;
} cli_t;

cli_t *cli_create(void);
void cli_destroy(cli_t *cli);

ngfw_ret_t cli_register_command(cli_t *cli, cli_command_t *cmd);
ngfw_ret_t cli_unregister_command(cli_t *cli, const char *name);

ngfw_ret_t cli_process_line(cli_t *cli, const char *line, cli_session_t *session);
ngfw_ret_t cli_process_file(cli_t *cli, const char *filename);

void cli_set_context(cli_t *cli, void *context);
void *cli_get_context(cli_t *cli);

ngfw_ret_t cli_run_interactive(cli_t *cli, int fd);
ngfw_ret_t cli_run_command(cli_t *cli, const char *command);

typedef struct cli_completion {
    char **matches;
    u32 count;
} cli_completion_t;

ngfw_ret_t cli_complete(cli_t *cli, const char *prefix, cli_completion_t *completion);

void cli_print(cli_session_t *session, const char *fmt, ...);
void cli_printf(cli_session_t *session, const char *fmt, ...);
void cli_error(cli_session_t *session, const char *fmt, ...);

cli_command_t *cli_find_command(cli_t *cli, const char *name);

#endif
