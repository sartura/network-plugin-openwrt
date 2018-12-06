/**
 * @file openwrt.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief wrapper for missing Terastram ubus call's in OpenWrt.
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

#include <libubox/blobmsg.h>
#include <json-c/json.h>
#include <sysrepo.h>

#include "sr_uci.h"
#include "openwrt.h"

static struct blob_buf bb;

static void
remove_newline(char *buf)
{
    int len;
    len = strlen(buf) - 1;
    if (buf[len] == '\n') {
        buf[len] = 0;
    }
}

static char *
single_space(char *str)
{
    char *from, *to;
    int space = 0;
    from = to = str;
    while(1) {
        if(space && *from == ' ' && to[-1] == ' ') {
            ++from;
        } else {
            space = (*from == ' ') ? 1 : 0;
            *to++ = *from++;
            if(!to[-1]) {
                break;
            }
        }
    }
    return str;
}


int
openwrt_rap(json_object *ret)
{
    int rc = SR_ERR_OK;
    FILE *arptable;
    void *t, *a;
    char line[512];
    char ipaddr[24];
    char macaddr[24];
    char device [16];
    char mask[8];
    char hw[8];
    char flag[8];
    char tmp[16];

    if ((arptable = fopen("/proc/net/arp", "r"))) {
        blob_buf_init(&bb, 0);
        a = blobmsg_open_array(&bb, "table");
        while(fgets(line, sizeof(line), arptable) != NULL) {
            remove_newline(line);
            if(sscanf(single_space(line), "%s %s %s %s %s %s %s", ipaddr, hw, flag, macaddr, mask, device, tmp) == 6) {
                t = blobmsg_open_table(&bb, NULL);
                blobmsg_add_string(&bb,"ipaddr", ipaddr);
                blobmsg_add_string(&bb,"hw", hw);
                blobmsg_add_string(&bb,"flags", flag);
                blobmsg_add_string(&bb,"macaddr", macaddr);
                blobmsg_add_string(&bb,"mask", mask);
                blobmsg_add_string(&bb,"device", device);
                blobmsg_close_table(&bb, t);
            }
        }
        fclose(arptable);
        blobmsg_close_array(&bb, a);
    } else {
        return SR_ERR_INTERNAL;
    }

    char *str = blobmsg_format_json(bb.head, true);
    CHECK_NULL_MSG(str, &rc, cleanup, "failed blobmsg_get_string()");
    ret = json_tokener_parse(str);
    CHECK_NULL_MSG(ret, &rc, cleanup, "failed json_tokener_parse()");

cleanup:
    return rc;
}

int
openwrt_ipv6_neigh(json_object *ret)
{
    int rc = SR_ERR_OK;
    FILE *ipv6nghtable;
    void *t, *a;
    char line[512];
    char ip6addr[128];
    char device[16];
    char macaddr[24];
    char router[16];
    char ip6status[16];

    if ((ipv6nghtable = popen("ip -6 neigh", "r"))) {
        blob_buf_init(&bb, 0);
        a = blobmsg_open_array(&bb, "neighbors");
        while(fgets(line, sizeof(line), ipv6nghtable) != NULL) {
        remove_newline(line);
            memset(router, '\0', sizeof(router));
            if(sscanf(single_space(line), "%s dev %s lladdr %s %s %s", ip6addr, device, macaddr, router, ip6status) == 5 ||
                sscanf(single_space(line), "%s dev %s lladdr %s %s", ip6addr, device, macaddr, ip6status) == 4) {
                t = blobmsg_open_table(&bb, NULL);
                blobmsg_add_string(&bb,"ip6addr", ip6addr);
                blobmsg_add_string(&bb,"device", device);
                blobmsg_add_string(&bb,"macaddr", macaddr);
                blobmsg_add_u8(&bb,"router", strstr(router, "router")?true:false);
                blobmsg_add_string(&bb,"ip6status", ip6status);
                blobmsg_close_table(&bb, t);
            }
        }
        pclose(ipv6nghtable);
        blobmsg_close_array(&bb, a);
    } else {
        return SR_ERR_INTERNAL;
    }

    char *str = blobmsg_format_json(bb.head, true);
    CHECK_NULL_MSG(str, &rc, cleanup, "failed blobmsg_get_string()");
    ret = json_tokener_parse(str);
    CHECK_NULL_MSG(ret, &rc, cleanup, "failed json_tokener_parse()");

cleanup:
    return rc;
}

/* get IPv6 link layer addresses
 * requires OpenWrt package ip-full
 */
int
openwrt_ipv6_link_local_address(json_object **ret)
{
    int rc = SR_ERR_OK;
    FILE *ip_a;
    void *t, *a;
    char line[512];
    char device[16];
    char ip6addr[132];
    int prefix;

    if ((ip_a = popen("ip -6 -br addr", "r"))) {
        blob_buf_init(&bb, 0);
        a = blobmsg_open_array(&bb, "ll_address");
        while(fgets(line, sizeof(line), ip_a) != NULL) {
            remove_newline(line);
            if ((sscanf(single_space(line), "%s UP %[^/]/%u", device, ip6addr, &prefix) == 3) ||
               (sscanf(single_space(line), "%s DOWN %[^/]/%u", device, ip6addr, &prefix) == 3) ||
               (sscanf(single_space(line), "%s UNKNOWN %[^/]/%u", device, ip6addr, &prefix) == 3) ||
               (sscanf(single_space(line), "%s %[^/]/%u", device, ip6addr, &prefix) == 3)) {
                t = blobmsg_open_table(&bb, NULL);
                blobmsg_add_string(&bb,"ip6addr", ip6addr);
                blobmsg_add_u16(&bb,"prefix", prefix);
                if (sscanf(single_space(line), "%s %s", device, ip6addr) == 2) {
                    blobmsg_add_string(&bb,"device", device);
                }
                blobmsg_close_table(&bb, t);
            }
        }
        pclose(ip_a);
        blobmsg_close_array(&bb, a);
    } else {
        return SR_ERR_INTERNAL;
    }

    char *str = blobmsg_format_json(bb.head, true);
    CHECK_NULL_MSG(str, &rc, cleanup, "failed blobmsg_get_string()");
    *ret = json_tokener_parse(str);
    free(str);
    CHECK_NULL_MSG(*ret, &rc, cleanup, "failed json_tokener_parse()");

cleanup:
    return rc;
}
