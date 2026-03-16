/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "ngfw/cli.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

static cli_command_t global_commands[] = {
    {
        .name = "help",
        .shortcut = "?",
        .description = "Show help information",
        .usage = "help [command]",
        .handler = NULL
    },
    {
        .name = "quit",
        .shortcut = "q",
        .description = "Exit the CLI",
        .usage = "quit",
        .handler = NULL
    },
    {
        .name = "exit",
        .shortcut = NULL,
        .description = "Exit the CLI",
        .usage = "exit",
        .handler = NULL
    },
    {
        .name = "show",
        .shortcut = NULL,
        .description = "Show system information",
        .usage = "show <options>",
        .handler = NULL,
        .children = NULL
    },
    {
        .name = "config",
        .shortcut = NULL,
        .description = "Configuration commands",
        .usage = "config <options>",
        .handler = NULL,
        .children = NULL
    },
    {
        .name = "filter",
        .shortcut = NULL,
        .description = "Filter management",
        .usage = "filter <options>",
        .handler = NULL,
        .children = NULL
    },
    {
        .name = "session",
        .shortcut = NULL,
        .description = "Session management",
        .usage = "session <options>",
        .handler = NULL,
        .children = NULL
    },
    {
        .name = "ips",
        .shortcut = NULL,
        .description = "IPS management",
        .usage = "ips <options>",
        .handler = NULL,
        .children = NULL
    },
    {
        .name = "log",
        .shortcut = NULL,
        .description = "Logging commands",
        .usage = "log <options>",
        .handler = NULL,
        .children = NULL
    },
    { NULL }
};

cli_t *cli_create(void)
{
    cli_t *cli = ngfw_malloc(sizeof(cli_t));
    if (!cli) return NULL;

    cli->commands = global_commands;
    cli->context = NULL;
    cli->sessions = NULL;
    cli->session_count = 0;

    return cli;
}

void cli_destroy(cli_t *cli)
{
    if (!cli) return;

    for (u32 i = 0; i < cli->session_count; i++) {
        if (cli->sessions[i]) {
            ngfw_free(cli->sessions[i]);
        }
    }
    ngfw_free(cli->sessions);
    ngfw_free(cli);
}

ngfw_ret_t cli_register_command(cli_t *cli, cli_command_t *cmd)
{
    if (!cli || !cmd) return NGFW_ERR_INVALID;
    
    cli_command_t *new_cmds = ngfw_malloc(sizeof(cli_command_t) * (cli->session_count + 2));
    if (!new_cmds) return NGFW_ERR_NO_MEM;
    
    memcpy(new_cmds, cli->commands, sizeof(cli_command_t) * cli->session_count);
    new_cmds[cli->session_count] = *cmd;
    new_cmds[cli->session_count + 1].name = NULL;
    
    if (cli->commands != global_commands) {
        ngfw_free(cli->commands);
    }
    cli->commands = new_cmds;
    
    return NGFW_OK;
}

ngfw_ret_t cli_unregister_command(cli_t *cli, const char *name)
{
    if (!cli || !name) return NGFW_ERR_INVALID;
    
    cli_command_t *cmds = cli->commands;
    for (u32 i = 0; cmds[i].name; i++) {
        if (strcmp(cmds[i].name, name) == 0) {
            for (u32 j = i; cmds[j].name; j++) {
                cmds[j] = cmds[j + 1];
            }
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

static char **cli_tokenize(const char *line, int *argc)
{
    static char *argv[64];
    char buffer[4096];
    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    *argc = 0;
    char *token = strtok(buffer, " \t\n");

    while (token && *argc < 64) {
        argv[*argc] = strdup(token);
        (*argc)++;
        token = strtok(NULL, " \t\n");
    }

    return argv;
}

static void cli_free_tokens(char **argv, int argc)
{
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
}

ngfw_ret_t cli_process_line(cli_t *cli, const char *line, cli_session_t *session)
{
    if (!cli || !line) return NGFW_ERR_INVALID;

    int argc = 0;
    char **argv = cli_tokenize(line, &argc);

    if (argc == 0) {
        cli_free_tokens(argv, argc);
        return CLI_CMD_OK;
    }

    cli_command_t *cmd = cli_find_command(cli, argv[0]);

    if (!cmd) {
        cli_error(session, "Unknown command: %s\n", argv[0]);
        cli_free_tokens(argv, argc);
        return CLI_CMD_INVALID;
    }

    if (strcmp(cmd->name, "help") == 0) {
        if (argc > 1) {
            cli_command_t *sub = cli_find_command(cli, argv[1]);
            if (sub) {
                cli_print(session, "Usage: %s\n", sub->usage);
                cli_print(session, "Description: %s\n", sub->description);
            } else {
                cli_error(session, "Unknown command: %s\n", argv[1]);
            }
        } else {
            cli_print(session, "Available commands:\n");
            for (cli_command_t *c = global_commands; c->name; c++) {
                cli_print(session, "  %-10s %s\n", c->name, c->description);
            }
        }
        cli_free_tokens(argv, argc);
        return CLI_CMD_HELP;
    }

    if (strcmp(cmd->name, "quit") == 0 || strcmp(cmd->name, "exit") == 0) {
        cli_free_tokens(argv, argc);
        return CLI_CMD_QUIT;
    }

    if (cmd->handler) {
        cli_cmd_result_t result = cmd->handler(argc, argv, cli->context);
        cli_free_tokens(argv, argc);
        return result;
    }

    cli_print(session, "Command '%s' not fully implemented\n", cmd->name);
    cli_free_tokens(argv, argc);
    return CLI_CMD_OK;
}

ngfw_ret_t cli_process_file(cli_t *cli, const char *filename)
{
    if (!cli || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "r");
    if (!fp) return NGFW_ERR_INVALID;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';

        if (line[0] == '#' || line[0] == '\0') continue;

        cli_run_command(cli, line);
    }

    fclose(fp);
    return NGFW_OK;
}

void cli_set_context(cli_t *cli, void *context)
{
    if (cli) cli->context = context;
}

void *cli_get_context(cli_t *cli)
{
    return cli ? cli->context : NULL;
}

ngfw_ret_t cli_run_interactive(cli_t *cli, int fd)
{
    if (!cli) return NGFW_ERR_INVALID;
    
    char line[4096];
    FILE *input = fdopen(fd, "r");
    if (!input) return NGFW_ERR;
    
    cli_session_t session = {
        .fd = fd,
        .interactive = true,
        .context = NULL
    };
    
    while (fgets(line, sizeof(line), input)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            break;
        }
        
        cli_process_line(cli, line, &session);
    }
    
    fclose(input);
    return NGFW_OK;
}

ngfw_ret_t cli_run_command(cli_t *cli, const char *command)
{
    cli_session_t session = {
        .fd = STDOUT_FILENO,
        .interactive = false,
        .context = NULL
    };

    return cli_process_line(cli, command, &session);
}

ngfw_ret_t cli_complete(cli_t *cli, const char *prefix, cli_completion_t *completion)
{
    if (!cli || !prefix || !completion) return NGFW_ERR_INVALID;
    
    memset(completion, 0, sizeof(cli_completion_t));
    
    size_t prefix_len = strlen(prefix);
    u32 match_count = 0;
    
    for (u32 i = 0; cli->commands[i].name; i++) {
        if (strncmp(cli->commands[i].name, prefix, prefix_len) == 0) {
            match_count++;
        }
    }
    
    if (match_count == 0) return NGFW_OK;
    
    completion->matches = ngfw_malloc(match_count * sizeof(char *));
    if (!completion->matches) return NGFW_ERR_NO_MEM;
    
    completion->count = 0;
    for (u32 i = 0; cli->commands[i].name; i++) {
        if (strncmp(cli->commands[i].name, prefix, prefix_len) == 0) {
            completion->matches[completion->count] = strdup(cli->commands[i].name);
            completion->count++;
        }
    }
    
    return NGFW_OK;
}

void cli_print(cli_session_t *session, const char *fmt, ...)
{
    if (!session) return;

    va_list args;
    va_start(args, fmt);
    vdprintf(session->fd, fmt, args);
    va_end(args);
}

void cli_printf(cli_session_t *session, const char *fmt, ...)
{
    cli_print(session, fmt);
}

void cli_error(cli_session_t *session, const char *fmt, ...)
{
    if (!session) return;

    dprintf(session->fd, "Error: ");
    va_list args;
    va_start(args, fmt);
    vdprintf(session->fd, fmt, args);
    va_end(args);
}

cli_command_t *cli_find_command(cli_t *cli, const char *name)
{
    if (!cli || !name) return NULL;

    for (cli_command_t *cmd = global_commands; cmd->name; cmd++) {
        if (strcmp(cmd->name, name) == 0) {
            return cmd;
        }
        if (cmd->shortcut && strcmp(cmd->shortcut, name) == 0) {
            return cmd;
        }
    }

    return NULL;
}
