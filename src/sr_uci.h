/**
 * @file sr_uci.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for sr_uci.c.
 *
 * @copyright
 * Copyright (C) 2018 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SR_UCI_H
#define SR_UCI_H

#include <sysrepo.h>
#include "sysrepo/plugins.h"

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#ifdef PLUGIN
#define ERR(MSG, ...) SRP_LOG_ERR(MSG, ...)
#define ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG)
#define WRN(MSG, ...) define SRP_LOG_WRN(MSG, ...)
#define WRN_MSG(MSG) define SRP_LOG_WRN_MSG(MSG)
#define INF(MSG, ...) SRP_LOG_INF(MSG, ...)
#define INF_MSG(MSG) SRP_LOG_INF_MSG(MSG)
#define DBG(MSG, ...) SRP_LOG_DBG(MSG, ...)
#define DBG_MSG(MSG) SRP_LOG_DBG_MSG(MSG)
#else
#define ERR(MSG, ...) SRP_LOG__STDERR(SR_LL_ERR, MSG, __VA_ARGS__)
#define ERR_MSG(MSG) SRP_LOG__STDERR(SR_LL_ERR, MSG "%s", "")
#define WRN(MSG, ...) SRP_LOG__STDERR(SR_LL_WRN, MSG, __VA_ARGS__)
#define WRN_MSG(MSG) SRP_LOG__STDERR(SR_LL_WRN, MSG "%s", "")
#define INF(MSG, ...) SRP_LOG__STDERR(SR_LL_INF, MSG, __VA_ARGS__)
#define INF_MSG(MSG) SRP_LOG__STDERR(SR_LL_INF, MSG "%s", "")
#define DBG(MSG, ...) SRP_LOG__STDERR(SR_LL_DBG, MSG, __VA_ARGS__)
#define DBG_MSG(MSG) SRP_LOG__STDERR(SR_LL_DBG, MSG "%s", "")
#endif

#define CHECK_RET_MSG(RET, LABEL, MSG)\
	do {\
		if (SR_ERR_OK != RET) {\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
			goto LABEL;\
		}\
	} while (0)

#define CHECK_RET(RET, LABEL, MSG, ...)\
	do {\
		if (SR_ERR_OK != RET) {\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)

#define CHECK_NULL_MSG(VALUE, RET, LABEL, MSG)\
	do {\
		if (NULL == VALUE) {\
			*RET = SR_ERR_INTERNAL;\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
			goto LABEL;\
		}\
	} while (0)

#define CHECK_NULL(VALUE, RET, LABEL, MSG, ...)\
	do {\
		if (NULL == VALUE) {\
			*RET = SR_ERR_INTERNAL;\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)

#define UCI_CHECK_RET_MSG(UCI_RET, SR_RET, LABEL, MSG)\
	do {\
		if (UCI_OK != UCI_RET) {\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
            *SR_RET = SR_ERR_INTERNAL;\
            goto LABEL;\
		}\
	} while (0)

#define UCI_CHECK_RET(UCI_RET, SR_RET, LABEL, MSG, ...)\
	do {\
		if (UCI_OK != UCI_RET) {\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
            *SR_RET = SR_ERR_INTERNAL;\
			goto LABEL;\
		}\
	} while (0)

#define UCI_CHECK_ITEM(VALUE, RET, LABEL, MSG, ...)\
	do {\
		if (NULL == VALUE) {\
			*RET = SR_ERR_NOT_FOUND;\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)

#define UBUS_CHECK_RET_MSG(RET, RC, LABEL, MSG)\
	do {\
		if (UBUS_STATUS_OK != RET) {\
			*RC = SR_ERR_INTERNAL;\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
			goto LABEL;\
		}\
	} while (0)

#define UBUS_CHECK_RET(RET, RC, LABEL, MSG, ...)\
	do {\
		if (UBUS_STATUS_OK != RET) {\
			*RC = SR_ERR_INTERNAL;\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)

typedef struct sr_uci_mapping_s sr_uci_mapping_t;

typedef struct sr_ctx_s {
    const char *yang_model;
    const char *config_file;
    struct uci_context *uctx;
    struct uci_package *package;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    sr_conn_ctx_t *startup_conn;
    sr_session_ctx_t *startup_sess;
    sr_uci_mapping_t *map;
    int map_size;
    void *data; //private data
    const char *uci_sections[];
} sr_ctx_t;

int get_uci_item(struct uci_context *, char *, char **);
int set_uci_item(struct uci_context *, char *, char *);

/* Configuration part of the plugin. */
struct sr_uci_mapping_s {
    char *ucipath;
    char *xpath;
};

/* list of sr_val_t values */
typedef struct sr_value_node_s {
    struct list_head head;
    sr_val_t value;
} sr_value_node_t;

char *get_n_key_value(char *, int);
char *new_path_key(char *, char *);
void del_path_key(char **);

#endif /* SR_UCI_H */
