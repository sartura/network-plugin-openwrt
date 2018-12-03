/**
 * @file ubus.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief fetch YANG state data via UBUS.
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

#include "sr_uci.h"
#include "ubus.h"
#include "network.h"

#define UBUS_INVOKE_TIMEOUT 2000

struct status_container {
    const char *ubus_method;
    sfp_ubus_val_to_sr_val transform;
    struct list_head *list;
};

struct ubus_context *ctx;
struct status_container *container_msg;

// remove mW, mV and A units from ubus result
static char *
remove_unit(const char *str)
{
    char *number = (char *) str;
    int i;

    for (i = 0; i < strlen(str); i++) {
        if (number[i] == ' ') {
            number[i] = '\0';
            break;
        }
    }

    return number;
}

static struct value_node *
insert_node(struct list_head *list, char *xpath)
{
    int rc = SR_ERR_OK;
    struct value_node *list_value = NULL;

    list_value = calloc(1, sizeof *list_value);
    CHECK_NULL_MSG(list_value, &rc, cleanup, "failed to calloc list_value");
    sr_new_val(xpath, &list_value->value);
    CHECK_NULL_MSG(list_value->value, &rc, cleanup, "failed sr_new_value");

    list_add(&list_value->head, list);

cleanup:
    return list_value;
}

static int
insert_sr_node(struct list_head *list, struct json_object *jobj, char *j_name, sr_type_t sr_type, char *xpath)
{
    int rc = SR_ERR_OK;
    double res = 0;
    char *end = NULL;
    const char *ubus_result = NULL;
    struct json_object *item = NULL;
    struct value_node *list_value = NULL;

    json_object_object_get_ex(jobj, j_name, &item);
    CHECK_NULL(jobj, &rc, cleanup, "failed json_object_object_get_ex for %s", j_name);

    ubus_result = json_object_get_string(item);
    CHECK_NULL_MSG(ubus_result, &rc, cleanup, "failed json_object_get_string");

    list_value = insert_node(list, xpath);
    CHECK_NULL_MSG(list_value, &rc, cleanup, "failed insert_node");

    list_value->value->type = sr_type;
    switch (sr_type) {
        case SR_BINARY_T:
        case SR_BITS_T:
        case SR_ENUM_T:
        case SR_IDENTITYREF_T:
        case SR_INSTANCEID_T:
        case SR_STRING_T:
            sr_val_set_str_data(list_value->value, sr_type, ubus_result);
            break;
        case SR_BOOL_T:
        case SR_DECIMAL64_T:
            INF("ubus_result |%s|\n\n", ubus_result);
            strtod(remove_unit(ubus_result), &end);
            list_value->value->data.decimal64_val = res;
            break;
        case SR_INT8_T:
            sscanf(ubus_result, "%" SCNd8, &list_value->value->data.int8_val);
            break;
        case SR_INT16_T:
            sscanf(ubus_result, "%" SCNd16, &list_value->value->data.int16_val);
            break;
        case SR_INT32_T:
            sscanf(ubus_result, "%" SCNd32, &list_value->value->data.int32_val);
            break;
        case SR_INT64_T:
            sscanf(ubus_result, "%" SCNd64, &list_value->value->data.int64_val);
            break;
        case SR_UINT8_T:
            sscanf(ubus_result, "%hhu", &list_value->value->data.uint8_val);
            break;
        case SR_UINT16_T:
            sscanf(ubus_result, "%hu", &list_value->value->data.uint16_val);
            break;
        case SR_UINT32_T:
            sscanf(ubus_result, "%" PRIu32, &list_value->value->data.uint32_val);
            break;
        case SR_UINT64_T:
            sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
            break;
        case SR_TREE_ITERATOR_T:
        default:
            rc = SR_ERR_INTERNAL;
            break;
    }

cleanup:
    return rc;
}

static char *
transform_state(const char *name)
{
    if (0 == strcmp(name, "INCOMPLETE")) {
        return "incomplete";
    } else if (0 == strcmp(name, "REACHABLE")) {
        return "reachable";
    } else if (0 == strcmp(name, "STALE")) {
        return "stale";
    } else if (0 == strcmp(name, "DELAY")) {
        return "delay";
    } else if (0 == strcmp(name, "PROBE")) {
        return "probe";
    } else {
        return "";
    }
}

static bool
is_l3_member(json_object *i, json_object *d, char *interface, char *device)
{
    struct json_object *res = NULL, *r;
    const char *l3_device = NULL;

    json_object_object_get_ex(i, "interface", &r);
    if (NULL == r)
        return res;

    int j;
    const int N = json_object_array_length(r);
    for (j = 0; j < N; j++) {
        json_object *item, *tmp;
        item = json_object_array_get_idx(r, j);
        json_object_object_get_ex(item, "interface", &tmp);
        if (NULL == tmp)
            continue;
        const char *j_name = json_object_get_string(tmp);
        if (0 == strcmp(j_name, interface) && strlen(interface) == strlen(j_name)) {
            json_object_object_get_ex(item, "l3_device", &tmp);
            if (!tmp)
                continue;
            l3_device = json_object_get_string(tmp);
            if (0 == strcmp(l3_device, device) && strlen(l3_device) == strlen(device)) {
                return true;
            }
        }
    }

    return false;
}

static struct json_object *
get_device_interface(json_object *i, json_object *d, char *name)
{
    struct json_object *res = NULL, *r;
    const char *l3_device = NULL;

    json_object_object_get_ex(i, "interface", &r);
    if (NULL == r)
        return res;

    int j;
    const int N = json_object_array_length(r);
    for (j = 0; j < N; j++) {
        json_object *item, *tmp;
        item = json_object_array_get_idx(r, j);
        if (NULL == item)
            continue;
        json_object_object_get_ex(item, "interface", &tmp);
        if (NULL == tmp)
            continue;
        const char *j_name = json_object_get_string(tmp);
        if (0 == strcmp(j_name, name) && strlen(name) == strlen(j_name)) {
            json_object_object_get_ex(item, "l3_device", &tmp);
            if (!tmp)
                continue;
            l3_device = json_object_get_string(tmp);
            break;
        }
    }

    json_object_object_foreach(d, key, val)
    {
        if (l3_device && 0 == strcmp(key, l3_device) && strlen(key) == strlen(l3_device)) {
            res = val;
            break;
        }
    }

    return res;
}

static struct json_object *
get_json_interface(json_object *obj, char *name)
{
    struct json_object *res = NULL, *r;

    json_object_object_get_ex(obj, "interface", &r);
    if (NULL == r)
        return res;

    int j;
    const int N = json_object_array_length(r);
    for (j = 0; j < N; j++) {
        json_object *item, *n;
        item = json_object_array_get_idx(r, j);
        json_object_object_get_ex(item, "interface", &n);
        if (NULL == n)
            continue;
        const char *j_name = json_object_get_string(n);
        if (0 == strcmp(j_name, name) && strlen(name) == strlen(j_name)) {
            res = item;
            break;
        }
    }

    return res;
}

int
network_operational_start()
{
    if (ctx)
        return SR_ERR_OK;
    INF("Connect ubus context. %zu", (size_t) ctx);
    container_msg = calloc(1, sizeof(*container_msg));

    ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        INF_MSG("Cant allocate ubus\n");
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

void
network_operational_stop()
{
    INF_MSG("Free ubus context.");
    INF("%lu %lu", (long unsigned) ctx, (long unsigned) container_msg);
    if (ctx)
        ubus_free(ctx);
    if (container_msg)
        free(container_msg);
}

static void
make_status_container(struct status_container **context,
                                  const char *ubus_method_to_call,
                                  sfp_ubus_val_to_sr_val result_function,
                                  struct list_head *list)
{
    *context = container_msg;
    (*context)->transform = result_function;
    (*context)->ubus_method = ubus_method_to_call;
    (*context)->list = list;
}

static void
ubus_base_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *json_string;
    struct json_object *base_object;

    struct status_container *status_container_msg;

    status_container_msg = (struct status_container *) req->priv;

    if (!msg) {
        return;
    }

    json_string = blobmsg_format_json(msg, true);
    base_object = json_tokener_parse(json_string);

    status_container_msg->transform(base_object, status_container_msg->list);

    json_object_put(base_object);
    free(json_string);
}

static int
ubus_base(const char *ubus_lookup_path, struct status_container *msg, struct blob_buf *blob)
{
    /* INF("list null %d", msg->list==NULL); */
    uint32_t id = 0;
    int u_rc = UBUS_STATUS_OK;
    int rc = SR_ERR_OK;

    u_rc = ubus_lookup_id(ctx, ubus_lookup_path, &id);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object %s", u_rc, ubus_lookup_path);

    u_rc = ubus_invoke(ctx, id, msg->ubus_method, blob->head, ubus_base_cb, (void *) msg, UBUS_INVOKE_TIMEOUT);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no method %s", u_rc, msg->ubus_method);

cleanup:
    blob_buf_free(blob);

    return rc;
}

static int
network_operational_operstatus(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *obj;
    const char *ubus_result;
    struct value_node *list_value;
    char xpath[MAX_XPATH];

    obj = get_json_interface(p_data->i, interface_name);
    CHECK_NULL_MSG(obj, &rc, cleanup, "failed get_json_interface()");

    json_object_object_get_ex(obj, "up", &t);
    CHECK_NULL(t, &rc, cleanup, "failed json_object_object_get_ex for %s", "up");
    ubus_result = json_object_get_string(t);
    CHECK_NULL_MSG(ubus_result, &rc, cleanup, "failed json_object_get_string");

    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/oper-status";
    sprintf(xpath, fmt, interface_name);
    list_value = insert_node(list, xpath);
    CHECK_NULL_MSG(list_value, &rc, cleanup, "failed insert_node");
    sr_val_set_str_data(list_value->value, SR_ENUM_T, !strcmp(ubus_result, "true") ? "up" : "down");

cleanup:
    return rc;
}

static int
network_operational_mac(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *i;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/phys-address";
    char xpath[MAX_XPATH];

    i = get_device_interface(p_data->i, p_data->d, interface_name);
    CHECK_NULL_MSG(i, &rc, cleanup, "failed get_device_interface()");

    sprintf(xpath, fmt, interface_name);
    rc = insert_sr_node(list, i, "macaddr", SR_STRING_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return rc;
}

static int
network_operational_rx(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *i;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/";
    char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

    i = get_device_interface(p_data->i, p_data->d, interface_name);
    CHECK_NULL_MSG(i, &rc, cleanup, "failed get_device_interface()");

    json_object_object_get_ex(i, "statistics", &i);
    CHECK_NULL(i, &rc, cleanup, "failed json_object_object_get_ex for %s", "statistics");

    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-octets");
    rc = insert_sr_node(list, i, "rx_bytes", SR_UINT64_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-discards");
    rc = insert_sr_node(list, i, "rx_dropped", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-errors");
    rc = insert_sr_node(list, i, "rx_errors", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-multicast-pkts");
    rc = insert_sr_node(list, i, "multicast", SR_UINT64_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return rc;
}

static int
network_operational_tx(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *i;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/";
    char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

    i = get_device_interface(p_data->i, p_data->d, interface_name);
    CHECK_NULL_MSG(i, &rc, cleanup, "failed get_device_interface()");

    json_object_object_get_ex(i, "statistics", &i);
    CHECK_NULL(i, &rc, cleanup, "failed json_object_object_get_ex for %s", "statistics");

    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-octets");
    rc = insert_sr_node(list, i, "tx_bytes", SR_UINT64_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-discards");
    rc = insert_sr_node(list, i, "tx_dropped", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-errors");
    rc = insert_sr_node(list, i, "tx_errors", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return rc;
}

static int
network_operational_mtu(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *i;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/mtu";
    const char *fmt6 = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv6/mtu";
    char xpath[MAX_XPATH];

    i = get_device_interface(p_data->i, p_data->d, interface_name);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "mtu", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT16_T;
    // fix 65536 > (2 ^ 16 - 1)
    if (0 == strcmp("65536", ubus_result)) {
        list_value->value->data.uint16_val =  65535;
    } else {
        sscanf(ubus_result, "%hu", &list_value->value->data.uint16_val);
    }
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "ipv6", &t);
    ubus_result = json_object_get_string(t);
    if (ubus_result && 0 == strncmp(ubus_result, "true", strlen(ubus_result))) {
        json_object_object_get_ex(i, "mtu6", &t);
        ubus_result = json_object_get_string(t);
        if (!ubus_result)
            return rc;
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sprintf(xpath, fmt6, interface_name);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_UINT32_T;
        sscanf(ubus_result, "%" PRIu32, &list_value->value->data.uint32_val);
        list_add(&list_value->head, list);
    }

    return rc;
}

static int
network_operational_ip(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    const char *ip;
    uint8_t prefix_length = 0;
    struct json_object *ip_obj;
    struct value_node *list_value;
    char xpath[MAX_XPATH];

    struct json_object *obj = get_json_interface(p_data->i, interface_name);
    if (!obj) {
        return rc;
    }

    json_object_object_get_ex(obj, "ipv4-address", &ip_obj);
    if (!ip_obj)
        return rc;

    int j;
    const int N = json_object_array_length(ip_obj);
    for (j = 0; j < N; j++) {
        struct json_object *t = json_object_array_get_idx(ip_obj, j);
        if (!t)
            continue;

        /* Get ip and mask (prefix length) from address. */
        struct json_object *a, *m;
        json_object_object_get_ex(t, "address", &a);
        if (!a)
            continue;
        ip = json_object_get_string(a);

        json_object_object_get_ex(t, "mask", &m);
        if (!a)
            continue;
        prefix_length = (uint8_t) json_object_get_int(m);

        const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length";
        sprintf(xpath, fmt, interface_name, ip);
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_UINT8_T;
        list_value->value->data.uint8_val = prefix_length;
        list_add(&list_value->head, list);
    }

    json_object_object_get_ex(obj, "ipv6-address", &ip_obj);
    if (!ip_obj)
        return rc;

    const int N6 = json_object_array_length(ip_obj);
    for (j = 0; j < N6; j++) {
        struct json_object *t = json_object_array_get_idx(ip_obj, j);
        if (!t)
            continue;

        /* Get ip and mask (prefix length) from address. */
        struct json_object *a, *m;
        json_object_object_get_ex(t, "address", &a);
        if (!a)
            continue;
        ip = json_object_get_string(a);

        json_object_object_get_ex(t, "mask", &m);
        if (!a)
            continue;
        prefix_length = (uint8_t) json_object_get_int(m);

        const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/prefix-length";
        sprintf(xpath, fmt, interface_name, ip);
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_UINT8_T;
        list_value->value->data.uint8_val = prefix_length;
        list_add(&list_value->head, list);
    }

    return rc;
}

static int
network_operational_neigh6(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *table, *iter_object;
    /* const char *ubus_result; */
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv6/neighbor[ip='%s']/%s";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(p_data->n, "neighbors", &table);
    CHECK_NULL(table, &rc, cleanup, "failed json_object_object_get_ex for %s", "neighbors");

    /* Get ip and mask (prefix length) from address. */
    const int N = json_object_array_length(table);
    struct value_node *list_value;
    for (int i = 0; i < N; i++) {
        json_object *ip_obj, *mac_obj, *device_obj, *router_obj, *status_obj;
        const char *ip, *mac, *device, *status;
        bool router;

        iter_object = json_object_array_get_idx(table, i);
        if (!iter_object)
            continue;

        json_object_object_get_ex(iter_object, "device", &device_obj);
        device = json_object_get_string(device_obj);
        if (!device)
            continue;
        if (!is_l3_member(p_data->i, p_data->d, interface_name, (char *) device))
            continue;

        json_object_object_get_ex(iter_object, "ip6addr", &ip_obj);
        json_object_object_get_ex(iter_object, "macaddr", &mac_obj);
        json_object_object_get_ex(iter_object, "router", &router_obj);
        json_object_object_get_ex(iter_object, "ip6status", &status_obj);
        ip = json_object_get_string(ip_obj);
        mac = json_object_get_string(mac_obj);
        router = json_object_get_boolean(router_obj);
        status = json_object_get_string(status_obj);
        if (!ip || !mac || !status)
            continue;

        sprintf(xpath, fmt, interface_name, ip, "link-layer-address");
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_STRING_T, mac);
        list_add(&list_value->head, list);

        sprintf(xpath, fmt, interface_name, ip, "state");
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_ENUM_T, transform_state(status));
        list_add(&list_value->head, list);

        if (!router)
            continue;
        sprintf(xpath, fmt, interface_name, ip, "is-router");
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_LEAF_EMPTY_T;
        list_add(&list_value->head, list);
    }

cleanup:
    return rc;
}

static int
network_operational_neigh(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *table, *iter_object;
    /* const char *ubus_result; */
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/neighbor[ip='%s']/link-layer-address";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(p_data->a, "table", &table);
    CHECK_NULL_MSG(table, &rc, cleanup, "failed json_object_object_get_ex");

    /* Get ip and mask (prefix length) from address. */
    const int N = json_object_array_length(table);
    struct value_node *list_value;
    for (int i = 0; i < N; i++) {
        json_object *ip_obj, *mac_obj, *device_obj;
        const char *ip, *mac, *device;

        iter_object = json_object_array_get_idx(table, i);
        if (!iter_object)
            continue;

        json_object_object_get_ex(iter_object, "device", &device_obj);
        if (!device_obj)
            continue;
        device = json_object_get_string(device_obj);
        if (!device)
            continue;
        if (!is_l3_member(p_data->i, p_data->d, interface_name, (char *) device))
            continue;

        json_object_object_get_ex(iter_object, "ipaddr", &ip_obj);
        if (!ip_obj)
            continue;
        json_object_object_get_ex(iter_object, "macaddr", &mac_obj);
        if (!mac_obj)
            continue;
        ip = json_object_get_string(ip_obj);
        mac = json_object_get_string(mac_obj);
        if (!ip || !mac)
            continue;

        sprintf(xpath, fmt, interface_name, ip);
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_STRING_T, mac);
        list_add(&list_value->head, list);
    }

cleanup:
    return rc;
}

int
operstatus_transform(priv_t *p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;

    //TODO some error's are critical
    rc = network_operational_operstatus(p_data, interface_name, list);
    INF("network_operational_operstatus: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_mac(p_data, interface_name, list);
    INF("network_operational_mac: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_rx(p_data, interface_name, list);
    INF("network_operational_rx: %s %S", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_tx(p_data, interface_name, list);
    INF("network_operational_tx: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_mtu(p_data, interface_name, list);
    INF("network_operational_mtu: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_ip(p_data, interface_name, list);
    INF("network_operational_ip: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_neigh(p_data, interface_name, list);
    INF("network_operational_neigh: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_neigh6(p_data, interface_name, list);
    INF("network_operational_neigh6: %s %s", interface_name, sr_strerror(rc));
    //CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

//cleanup:
    return SR_ERR_OK;
}

static void
sfp_rx_pwr_cb(struct json_object *obj, struct list_head *list)
{
    int rc = SR_ERR_OK;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:rx-pwr";

    rc = insert_sr_node(list, obj, "rx-pwr", SR_DECIMAL64_T, (char *) fmt);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return;
}

static void
sfp_tx_pwr_cb(struct json_object *obj, struct list_head *list)
{
    int rc = SR_ERR_OK;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:tx-pwr";

    rc = insert_sr_node(list, obj, "tx-pwr", SR_DECIMAL64_T, (char *) fmt);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return;
}

static void
sfp_current_cb(struct json_object *obj, struct list_head *list)
{
    int rc = SR_ERR_OK;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:current";

    rc = insert_sr_node(list, obj, "current", SR_DECIMAL64_T, (char *) fmt);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return;
}

static void
sfp_voltage_cb(struct json_object *obj, struct list_head *list)
{
    int rc = SR_ERR_OK;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:voltage";

    rc = insert_sr_node(list, obj, "voltage", SR_DECIMAL64_T, (char *) fmt);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return;
}

int
sfp_state_data(struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct status_container *msg = NULL;
    struct blob_buf buf = {0};

    make_status_container(&msg, "get-rx-pwr", sfp_rx_pwr_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    blob_buf_init(&buf, 0);
    make_status_container(&msg, "get-tx-pwr", sfp_tx_pwr_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    blob_buf_init(&buf, 0);
    make_status_container(&msg, "get-current", sfp_current_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    blob_buf_init(&buf, 0);
    make_status_container(&msg, "get-voltage", sfp_voltage_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

cleanup:
    return rc;
}

int
phy_interfaces_state_cb(priv_t * p_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *i;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/";
    char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

    json_object_object_foreach(p_data->d, key, val)
    {
        if (0 == strcmp(key, interface_name) && strlen(key) == strlen(interface_name)) {
            i = val;
            break;
        }
    }

    /* add type */
    snprintf(xpath, MAX_XPATH, "%s%s", base, "type");
    list_value = insert_node(list, xpath);
    CHECK_NULL_MSG(list_value, &rc, cleanup, "failed insert_node");
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_IDENTITYREF_T, "iana-if-type:ethernetCsmacd");

    snprintf(xpath, MAX_XPATH, "%s%s", base, "phys-address");
    rc = insert_sr_node(list, i, "macaddr", SR_STRING_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    json_object_object_get_ex(i, "carrier", &t);
    CHECK_NULL_MSG(t, &rc, cleanup, "failed json_object_object_get_ex");
    ubus_result = json_object_get_string(t);
    CHECK_NULL_MSG(ubus_result, &rc, cleanup, "failed json_object_get_string");
    snprintf(xpath, MAX_XPATH, "%s%s", base, "oper-status");
    list_value = insert_node(list, xpath);
    CHECK_NULL_MSG(list_value, &rc, cleanup, "failed insert_node");
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_ENUM_T, !strcmp(ubus_result, "true") ? "up" : "down");

    /* get statistics data */
    json_object_object_get_ex(i, "statistics", &i);
    CHECK_NULL_MSG(i, &rc, cleanup, "failed json_object_object_get_ex");
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-octets");
    rc = insert_sr_node(list, i, "rx_bytes", SR_UINT64_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-discards");
    rc = insert_sr_node(list, i, "rx_dropped", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-errors");
    rc = insert_sr_node(list, i, "rx_errors", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-multicast-pkts");
    rc = insert_sr_node(list, i, "multicast", SR_UINT64_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/in-octets");
    rc = insert_sr_node(list, i, "tx_bytes", SR_UINT64_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/in-discards");
    rc = insert_sr_node(list, i, "tx_dropped", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/in-errors");
    rc = insert_sr_node(list, i, "tx_errors", SR_UINT32_T, xpath);
    CHECK_RET(rc, cleanup, "failed insert_sr_node: %s", sr_strerror(rc));

cleanup:
    return rc;
}
