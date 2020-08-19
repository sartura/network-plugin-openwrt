#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <srpo_uci.h>
#include <srpo_ubus.h>

#include "transform_data.h"
#include "utils/memory.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define NETWORK_YANG_MODEL "ietf-interfaces"
#define SYSREPOCFG_EMPTY_CHECK_COMMAND "sysrepocfg -X -d running -m " NETWORK_YANG_MODEL
#define NETWORK_INTERFACE_XPATH_TEMPLATE "/" NETWORK_YANG_MODEL ":interfaces/interface[name='%s']"
#define NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/" NETWORK_YANG_MODEL ":interfaces-state"

typedef char *(*transform_data_cb)(const char *);

typedef struct {
	const char *value_name;
	const char *xpath_template;
	transform_data_cb transform_data;
} network_ubus_json_transform_table_t;

int network_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void network_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int network_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int network_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static bool network_running_datastore_is_empty_check(void);
static int network_uci_data_load(sr_session_ctx_t *session);
static char *network_xpath_get(const struct lyd_node *node);

static void network_ubus(const char *ubus_json, srpo_ubus_result_values_t *values);
static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent);

srpo_uci_xpath_uci_template_map_t network_xpath_uci_path_template_map[] = {
	{NETWORK_INTERFACE_XPATH_TEMPLATE "network.%s", "interface", NULL, NULL, false, false},
	{NETWORK_INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/mtu", "network.%s.mtu", NULL, NULL, NULL, false, false},
	{NETWORK_INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/mtu", "network.%s.mtu", NULL, NULL, NULL, false, false},
	{NETWORK_INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/enabled", "network.%s.enabled", NULL, transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{NETWORK_INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/enabled", "network.%s.enabled", NULL, transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
};

srpo_uci_xpath_uci_template_map_t network_xpath_uci_path_unnamed_template_map[] = {
	{"/ietf-ip:ipv4/address[ip='%s']/ip", "network.%s.ipaddr", NULL, NULL, NULL, false, false},
	{"/ietf-ip:ipv6/address[ip='%s']/ip", "network.%s.ip6addr", NULL, NULL, NULL, false, false},
	{"/ietf-ip:ipv4/address[ip='%s']/prefix-length", "network.%s.ip4prefixlen", NULL, NULL, NULL, false, false},
	{"/ietf-ip:ipv6/address[ip='%s']/prefix-length", "network.%s.ip6prefixlen", NULL, NULL, NULL, false, false},
	{"/ietf-ip:ipv4/address[ip='%s']/netmask", "network.%s.netmask", NULL, NULL, NULL, false, false},
};

static network_ubus_json_transform_table_t network_transform_table[] = {
	{.value_name = "type", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/type"},
	{.value_name = "admin-status", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/admin-status"},
	{.value_name = "oper-status", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/oper_status"},
	{.value_name = "last-change", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/last-change"},
	{.value_name = "if-index", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/if-index"},
	{.value_name = "phys-address", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/phys-address"},
	{.value_name = "speed", .xpath_template = NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE "/speed"},
};

static const char *network_uci_sections[] = {"interface"};
static const char *network_uci_unnamed_sections[] = {"interface"};
static const char *network_ubus_object_paths[] = {"network.device", "network.interface", "network.interface", "sfp.ddm", "router.net", "router.net"};
static const char *network_ubus_object_methods[] = {"status", "status", "dump", "get-all", "arp", "ipv6-neigh"};

static struct {
	const char *uci_file;
	const char **uci_section_list;
	size_t uci_section_list_size;
	bool convert_unnamed_sections;
} network_config_files[] = {
	{"network", network_uci_sections, ARRAY_SIZE(network_uci_sections), true},
	{"network", network_uci_unnamed_sections, ARRAY_SIZE(network_uci_unnamed_sections), false},
};

int network_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	error = srpo_uci_init();
	if (error) {
		SRP_LOG_ERR("srpo_uci_init error (%d): %s", error, srpo_uci_error_description_get(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	*private_data = startup_session;

	if (network_running_datastore_is_empty_check() == true) {
		SRP_LOG_INFMSG("running DS is empty, loading data from UCI");

		error = network_uci_data_load(session);
		if (error) {
			SRP_LOG_ERRMSG("network_uci_data_load error");
			goto error_out;
		}

		error = sr_copy_config(startup_session, NETWORK_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	SRP_LOG_INFMSG("subscribing to module change");
	error = sr_module_change_subscribe(session, NETWORK_YANG_MODEL, "/" NETWORK_YANG_MODEL ":*//* ", network_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, NETWORK_YANG_MODEL, "/ietf-interfaces:interfaces-state", network_state_data_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("plugin init done");

	goto out;

error_out:
	sr_unsubscribe(subscription);

out:
	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static bool network_running_datastore_is_empty_check(void)
{
	FILE *sysrepocfg_DS_empty_check = NULL;
	bool is_empty = false;

	sysrepocfg_DS_empty_check = popen(SYSREPOCFG_EMPTY_CHECK_COMMAND, "r");
	if (sysrepocfg_DS_empty_check == NULL) {
		SRP_LOG_WRN("could not execute %s", SYSREPOCFG_EMPTY_CHECK_COMMAND);
		is_empty = true;
		goto out;
	}

	if (fgetc(sysrepocfg_DS_empty_check) == EOF) {
		is_empty = true;
	}

out:
	if (sysrepocfg_DS_empty_check) {
		pclose(sysrepocfg_DS_empty_check);
	}

	return is_empty;
}

static int network_uci_data_load(sr_session_ctx_t *session)
{
	int error = 0;
	char **uci_path_list = NULL;
	size_t uci_path_list_size = 0;
	char *xpath = NULL;
	srpo_uci_transform_data_cb transform_uci_data_cb = NULL;
	bool has_transform_uci_data_private = false;
	char *uci_section_name = NULL;
	char **uci_value_list = NULL;
	size_t uci_value_list_size = 0;
	srpo_uci_xpath_uci_template_map_t *template_map = NULL;
	size_t template_map_size = 0;

	for (size_t i = 0; i < ARRAY_SIZE(network_config_files); i++) {

		if (network_config_files[i].convert_unnamed_sections) {
			template_map = network_xpath_uci_path_template_map;
			template_map_size = ARRAY_SIZE(network_xpath_uci_path_template_map);
		} else {
			template_map = network_xpath_uci_path_unnamed_template_map;
			template_map_size = ARRAY_SIZE(network_xpath_uci_path_unnamed_template_map);
		}

		error = srpo_uci_ucipath_list_get(network_config_files[i].uci_file, network_config_files[i].uci_section_list, network_config_files[i].uci_section_list_size, &uci_path_list, &uci_path_list_size, network_config_files[i].convert_unnamed_sections);
		if (error) {
			SRP_LOG_ERR("srpo_uci_path_list_get error (%d): %s", error, srpo_uci_error_description_get(error));
			goto error_out;
		}

		for (size_t j = 0; j < uci_path_list_size; j++) {
			if (network_config_files[i].convert_unnamed_sections) {
				error = srpo_uci_ucipath_to_xpath_convert(uci_path_list[j], template_map, template_map_size, &xpath);
			} else {
				error = srpo_uci_sublist_ucipath_to_xpath_convert(uci_path_list[j], NETWORK_INTERFACE_XPATH_TEMPLATE, "network.%s", template_map, template_map_size, &xpath);
			}

			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_to_xpath_path_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				FREE_SAFE(uci_path_list[j]);
				continue;
			}

			error = srpo_uci_transform_uci_data_cb_get(uci_path_list[j], template_map, template_map_size,
													   &transform_uci_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_uci_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_uci_data_private_get(uci_path_list[j], template_map, template_map_size, &has_transform_uci_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_uci_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path_list[j]);

			error = srpo_uci_element_value_get(uci_path_list[j], transform_uci_data_cb, has_transform_uci_data_private ? uci_section_name : NULL, &uci_value_list, &uci_value_list_size);
			if (error) {
				SRP_LOG_ERR("srpo_uci_element_value_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			for (size_t k = 0; k < uci_value_list_size; k++) {
				error = sr_set_item_str(session, xpath, uci_value_list[k], NULL, SR_EDIT_DEFAULT);
				if (error) {
					SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
					goto error_out;
				}

				FREE_SAFE(uci_value_list[k]);
			}

			FREE_SAFE(uci_section_name);
			FREE_SAFE(uci_path_list[j]);
			FREE_SAFE(xpath);
		}

		/*
		 * FIXME: libuci otherwise checks the context for existing file
		 * in `uci_switch_config` and throws `UCI_ERR_DUPLICATE`.
		 */
		srpo_uci_cleanup();
		error = srpo_uci_init();
		if (error) {
			SRP_LOG_ERR("srpo_uci_init error (%d): %s", error, srpo_uci_error_description_get(error));
			goto error_out;
		}
	}

	error = sr_apply_changes(session, 0, 0);
	if (error) {
		SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	goto out;

error_out:
	FREE_SAFE(xpath);
	FREE_SAFE(uci_section_name);

	for (size_t i = 0; i < uci_path_list_size; i++) {
		FREE_SAFE(uci_path_list[i]);
	}

	FREE_SAFE(uci_path_list);

	for (size_t i = 0; i < uci_value_list_size; i++) {
		FREE_SAFE(uci_value_list[i]);
	}

	FREE_SAFE(uci_value_list);

out:
	return error ? -1 : 0;
}

void network_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	srpo_uci_cleanup();

	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int network_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;
	sr_change_iter_t *network_server_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;
	char *node_xpath = NULL;
	const char *node_value = NULL;
	char *uci_path = NULL;
	struct lyd_node_leaf_list *node_leaf_list;
	struct lys_node_leaf *schema_node_leaf;
	srpo_uci_transform_data_cb transform_sysrepo_data_cb = NULL;
	bool has_transform_sysrepo_data_private = false;
	const char *uci_section_type = NULL;
	char *uci_section_name = NULL;
	void *transform_cb_data = NULL;

	SRP_LOG_INF("module_name: %s, xpath: %s, event: %d, request_id: %" PRIu32, module_name, xpath, event, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto error_out;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, NETWORK_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &network_server_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}

		while (sr_get_change_tree_next(session, network_server_change_iter, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = network_xpath_get(node);
			error = srpo_uci_xpath_to_ucipath_convert(node_xpath, network_xpath_uci_path_template_map, ARRAY_SIZE(network_xpath_uci_path_template_map), &uci_path);
			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_xpath_to_ucipath_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				error = 0;
				SRP_LOG_DBG("xpath %s not found in table", node_xpath);
				FREE_SAFE(node_xpath);
				continue;
			}

			error = srpo_uci_transform_sysrepo_data_cb_get(node_xpath, network_xpath_uci_path_template_map, ARRAY_SIZE(network_xpath_uci_path_template_map), &transform_sysrepo_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_sysrepo_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_sysrepo_data_private_get(node_xpath, network_xpath_uci_path_template_map, ARRAY_SIZE(network_xpath_uci_path_template_map), &has_transform_sysrepo_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_sysrepo_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_section_type_get(uci_path, network_xpath_uci_path_template_map, ARRAY_SIZE(network_xpath_uci_path_template_map), &uci_section_type);
			if (error) {
				SRP_LOG_ERR("srpo_uci_section_type_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path);

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_leaf_list = (struct lyd_node_leaf_list *) node;
				node_value = node_leaf_list->value_str;
				if (node_value == NULL) {
					schema_node_leaf = (struct lys_node_leaf *) node_leaf_list->schema;
					node_value = schema_node_leaf->dflt ? schema_node_leaf->dflt : "";
				}
			}

			SRP_LOG_DBG("uci_path: %s; prev_val: %s; node_val: %s; operation: %d", uci_path, prev_value, node_value, operation);

			if (node->schema->nodetype == LYS_LIST) {
				if (operation == SR_OP_CREATED) {
					error = srpo_uci_section_create(uci_path, uci_section_type);
					if (error) {
						SRP_LOG_ERR("srpo_uci_section_create error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_section_delete(uci_path);
					if (error) {
						SRP_LOG_ERR("srpo_uci_section_delete error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAF) {
				if (operation == SR_OP_CREATED || operation == SR_OP_MODIFIED) {
					if (has_transform_sysrepo_data_private && strstr(node_xpath, "stop")) {
						transform_cb_data = (void *) &(leasetime_data_t){.uci_section_name = uci_section_name, .sr_session = session};

					} else if (has_transform_sysrepo_data_private) {
						transform_cb_data = uci_section_name;
					} else {
						transform_cb_data = NULL;
					}

					error = srpo_uci_option_set(uci_path, node_value, transform_sysrepo_data_cb, transform_cb_data);
					if (error) {
						SRP_LOG_ERR("srpo_uci_option_set error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_option_remove(uci_path);
					if (error) {
						SRP_LOG_ERR("srpo_uci_option_remove error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAFLIST) {
				if (has_transform_sysrepo_data_private) {
					transform_cb_data = uci_section_name;
				} else {
					transform_cb_data = NULL;
				}

				if (operation == SR_OP_CREATED) {
					error = srpo_uci_list_set(uci_path, node_value, transform_sysrepo_data_cb, transform_cb_data);
					if (error) {
						SRP_LOG_ERR("srpo_uci_list_set error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_list_remove(uci_path, node_value);
					if (error) {
						SRP_LOG_ERR("srpo_uci_list_remove error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			}
			FREE_SAFE(uci_section_name);
			FREE_SAFE(uci_path);
			FREE_SAFE(node_xpath);
			node_value = NULL;
		}

		srpo_uci_commit("network");
	}

	goto out;

error_out:
	srpo_uci_revert("network");

out:
	FREE_SAFE(uci_section_name);
	FREE_SAFE(node_xpath);
	FREE_SAFE(uci_path);
	sr_free_change_iter(network_server_change_iter);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static char *network_xpath_get(const struct lyd_node *node)
{
	char *xpath_node = NULL;
	char *xpath_leaflist_open_bracket = NULL;
	size_t xpath_trimed_size = 0;
	char *xpath_trimed = NULL;

	if (node->schema->nodetype == LYS_LEAFLIST) {
		xpath_node = lyd_path(node);
		xpath_leaflist_open_bracket = strrchr(xpath_node, '[');
		if (xpath_leaflist_open_bracket == NULL) {
			return xpath_node;
		}

		xpath_trimed_size = (size_t) xpath_leaflist_open_bracket - (size_t) xpath_node + 1;
		xpath_trimed = xcalloc(1, xpath_trimed_size);
		strncpy(xpath_trimed, xpath_node, xpath_trimed_size - 1);
		xpath_trimed[xpath_trimed_size - 1] = '\0';

		FREE_SAFE(xpath_node);

		return xpath_trimed;
	} else {
		return lyd_path(node);
	}
}

static int network_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data = {.lookup_path = NULL, .method = NULL, .transform_data_cb = network_ubus, .timeout = 0, .json_call_arguments = NULL};
	int error = SRPO_UBUS_ERR_OK;

	if (!strcmp(path, NETWORK_INTERFACES_STATE_DATA_XPATH_TEMPLATE) || !strcmp(path, "*")) {
		srpo_ubus_init_result_values(&values);

		for (size_t i = 0; i < ARRAY_SIZE(network_ubus_object_methods); i++) {
			ubus_call_data.lookup_path = network_ubus_object_methods[i];
			ubus_call_data.method = network_ubus_object_paths[i];

			error = srpo_ubus_call(values, &ubus_call_data);
			if (error != SRPO_UBUS_ERR_OK) {
				SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
				goto out;
			}
		}
		/*
		ubus_call_data.lookup_path = "router.net";
		ubus_call_data.method = "arp";
		error = srpo_ubus_call(values, &ubus_call_data);
		if (error != SRPO_UBUS_ERR_OK) {
			FILE *arptable = NULL;
			char line[512];
			json_object *;

			arptable = fopen("/proc/net/arp", "r");
			json_arptable = json_object_from_file(arptable);

			while (fgets(line, sizeof(line), arptable) != NULL) {
				json_object_string
			}
			fclose(arptable);

			SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
		}

		ubus_call_data.method = "ipv6-neigh";
		error = srpo_ubus_call(values, &ubus_call_data);
		if (error != SRPO_UBUS_ERR_OK) {
			//TODO openwrt_ipv6_neigh
			SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto out;
		}
*/
		error = store_ubus_values_to_datastore(session, request_xpath, values, parent);
		if (error) {
			SRP_LOG_ERR("store_ubus_values_to_datastore error (%d)", error);
			goto out;
		}
		srpo_ubus_free_result_values(values);
		values = NULL;
	}

out:
	if (values) {
		srpo_ubus_free_result_values(values);
	}

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static void network_ubus(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	json_object *result = NULL;
	json_object *child_value = NULL;
	const char *value_string = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);

	json_object_object_foreach(result, key, value)
	{
		for (size_t i = 0; i < ARRAY_SIZE(network_transform_table); i++) {
			json_object_object_get_ex(value, network_transform_table[i].value_name, &child_value);
			if (child_value == NULL) {
				goto cleanup;
			}

			value_string = json_object_get_string(child_value);

			error = srpo_ubus_result_values_add(values, value_string, strlen(value_string), network_transform_table[i].xpath_template, strlen(network_transform_table[i].xpath_template), key, strlen(key));
			if (error != SRPO_UBUS_ERR_OK) {
				goto cleanup;
			}
		}
	}

cleanup:
	json_object_put(result);
	return;
}

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent)
{
	const struct ly_ctx *ly_ctx = NULL;
	if (*parent == NULL) {
		ly_ctx = sr_get_context(sr_session_get_connection(session));
		if (ly_ctx == NULL) {
			return -1;
		}
		*parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
	}

	for (size_t i = 0; i < values->num_values; i++) {
		lyd_new_path(*parent, NULL, values->values[i].xpath, values->values[i].value, 0, 0);
	}

	return 0;
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main()
{
	int error = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_data = NULL;

	sr_log_stderr(SR_LL_DBG);

	/* connect to sysrepo */
	error = sr_connect(SR_CONN_DEFAULT, &connection);
	if (error) {
		SRP_LOG_ERR("sr_connect error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = network_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("network_plugin_init_cb error");
		goto out;
	}

	/*  loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);
	}

out:
	network_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
