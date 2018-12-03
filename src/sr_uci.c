/**
 * @file sr_uci.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief Contains generic sysrepo to UCI operations.
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

#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uci.h>
#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "sr_uci.h"

/* get uci option */
int get_uci_item(struct uci_context *uctx, char *ucipath, char **value) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr;

    char *path = malloc(sizeof(char) * (strlen(ucipath) + 1));
    CHECK_NULL(path, &rc, cleanup, "malloc %s", ucipath);
    sprintf(path, "%s", ucipath);

    uci_ret = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, path);
    UCI_CHECK_ITEM(ptr.o, &rc, cleanup, "Uci item %s not found", ucipath);
    UCI_CHECK_ITEM(ptr.o->v.string, &rc, cleanup, "Uci item %s not found", ucipath);

    *value = strdup(ptr.o->v.string);
    CHECK_NULL(*value, &rc, cleanup, "strdup failed for %s", ucipath);

cleanup:
    if (NULL != path) {
        free(path);
    }
    return rc;
}

/* set uci option */
int set_uci_item(struct uci_context *uctx, char *ucipath, char *value) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr;

    char *path = malloc(sizeof(char) * (strlen(ucipath) + strlen(value) + 2));
    CHECK_NULL_MSG(path, &rc, cleanup, "malloc failed");

    sprintf(path, "%s%s%s", ucipath, "=", value);

    uci_ret = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, path);

    uci_ret = uci_set(uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", uci_ret, path);

    uci_ret = uci_save(uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", uci_ret, path);

    uci_ret = uci_commit(uctx, &(ptr.p), false);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", uci_ret, path);

cleanup:
    if (NULL != path) {
        free(path);
    }
    return rc;
}

/* insert key value into a xpath or ucipath with snprintf */
char *new_path_key(char *path, char *key) {
    int rc = SR_ERR_OK;
    char *value = NULL;
    int len = 0;

    CHECK_NULL_MSG(path, &rc, cleanup, "missing parameter path");

    /* if the xpath does not contain list elements, copy string */
    if (NULL == key) {
        return strdup(path);
    }

    len = strlen(key) + strlen(path);

    value = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(value, &rc, cleanup, "failed malloc");

    snprintf(value, len, path, key);

cleanup:
    return value;
}

/* free the memory from new_path_key and set to NULL */
void del_path_key(char **value) {
    if (NULL == *value) {
        return;
    }
    free(*value);
    *value = NULL;
}

/* get the first key value from a sysrepo XPATH */
char *get_key_value(char *orig_xpath)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto cleanup;
    }
    while (true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            key = strdup(sr_xpath_next_key_value(NULL, &state));
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

cleanup:
    sr_xpath_recover(&state);
    return key;
}

/* get the n-th (0 is first) key value from a sysrepo XPATH */
char *get_n_key_value(char *orig_xpath, int n)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};
    int counter = 0;

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto cleanup;
    }
    while (true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            if (counter++ != n) {
                continue;
            }

            key = strdup(sr_xpath_next_key_value(NULL, &state));
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

cleanup:
    sr_xpath_recover(&state);
    return key;
}

/* check if two strings are equal */
bool string_eq(char *first, char *second)
{
    if (0 == strcmp(first, second) && (strlen(first) == strlen(second))) {
        return true;
    } else {
        return false;
    }
}

/* Per convention, boolean options may have one of the values '0', 'no',
 * 'off', 'false' or 'disabled' to specify a false value or '1' , 'yes',
 * 'on', 'true' or 'enabled' to specify a true value. */
bool uci_true_value(char *uci_val)
{
    if (string_eq("1", uci_val)) {
        return true;
    } else if (string_eq("yes", uci_val)) {
        return true;
    } else if (string_eq("on", uci_val)) {
        return true;
    } else if (string_eq("true", uci_val)) {
        return true;
    } else if (string_eq("enabled", uci_val)) {
        return true;
    } else {
        return false;
    }
}
