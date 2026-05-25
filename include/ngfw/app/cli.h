/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_APP_CLI_H
#define NGFW_APP_CLI_H

#include "ngfw/types.h"

/*
 * Command Line Interface
 */

typedef struct cli cli_t;

cli_t *cli_create(void);
void cli_destroy(cli_t *cli);

ngfw_ret_t cli_init(cli_t *cli);
ngfw_ret_t cli_start(cli_t *cli);
ngfw_ret_t cli_stop(cli_t *cli);

ngfw_ret_t cli_register_command(cli_t *cli, const char *cmd, const char *help, 
                                 int (*handler)(int argc, char **argv));

#endif
