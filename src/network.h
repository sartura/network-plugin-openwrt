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

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>
#include <sysrepo/plugins.h>

#include "sr_uci.h"
#include "uci.h"

#define MAX_UCI_PATH 64
#define MAX_XPATH 256

#define ARR_SIZE(a) sizeof a / sizeof a[0]

typedef struct priv_s {
    json_object *i; // ubus call network.interface dump
    json_object *d; // ubus call network.device status
    json_object *a; // ubus call router.net arp
    json_object *n; // ubus call router.net ipv6_neigh
    json_object *tmp;
    bool terastream; // is the terastream YANG model installed
} priv_t;

#endif /* NETWORK_H */
