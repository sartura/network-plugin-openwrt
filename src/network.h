/**
 * @file network.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for network.c.
 *
 * @copyright
 * Copyright (C) 2018 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "terastream.h"

#define MAX_XPATH 256

struct value_node {
    struct list_head head;
    sr_val_t *value;
};

typedef void (*ubus_val_to_sr_val)(priv_t *, char *, struct list_head *list);
typedef void (*sfp_ubus_val_to_sr_val)(struct json_object *, struct list_head *list);

int network_operational_start();
void network_operational_stop();

int operstatus_transform(priv_t *, char *, struct list_head *);

int sfp_state_data(struct list_head *);

int phy_interfaces_state_cb(priv_t *, char *, struct list_head *);
int sfp_data_cb(struct json_object *, struct list_head *);

#endif /* NETWORK_H */
