/**
 * @file openwrt.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for openwrt.c.
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

#ifndef OPENWRT_H
#define OPENWRT_H

#include <json-c/json.h>

int openwrt_rap(json_object **);
int openwrt_ipv6_neigh(json_object **);
int openwrt_ipv6_link_local_address(json_object **);

#endif /* OPENWRT_H */
