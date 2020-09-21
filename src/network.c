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

#define INTERFACES_YANG_PATH "/" NETWORK_YANG_MODEL ":interfaces"
#define INTERFACES_STATE_YANG_PATH "/" NETWORK_YANG_MODEL ":interfaces-state"
#define INTERFACE_XPATH_TEMPLATE INTERFACES_YANG_PATH "/interface[name='%s']"

typedef char *(*transform_data_cb)(const char *);

typedef struct {
	const char *value_name;
	const char *xpath_template;
	transform_data_cb transform_data;

} network_ubus_json_transform_table_t;

const char *IPADDR_UCI_TEMPLATE = "network.%s.ipaddr";
const char *IP6ADDR_UCI_TEMPLATE = "network.%s.ip6addr";

static int network_module_change_cb(sr_session_ctx_t *session, const char *module_name,
									const char *xpath, sr_event_t event, uint32_t request_id,
									void *private_data);
static int network_state_data_cb(sr_session_ctx_t *session, const char *module_name,
								 const char *path, const char *request_xpath, uint32_t request_id,
								 struct lyd_node **parent, void *private_data);

static int transform_path_address_cb(const char *target, const char *from, const char *to,
									 srpo_uci_path_direction_t direction, char **path);

static bool network_running_datastore_is_empty_check(void);
static int network_uci_data_load(sr_session_ctx_t *session);
static char *network_xpath_get(const struct lyd_node *node);

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath,
										  srpo_ubus_result_values_t *values, struct lyd_node **parent);

srpo_uci_xpath_uci_template_map_t network_xpath_uci_path_template_map[] = {
	{INTERFACE_XPATH_TEMPLATE, "network.%s", "interface", NULL, NULL, NULL, false, false},
	{INTERFACE_XPATH_TEMPLATE "/type", "network.%s.proto", NULL,
	 NULL, transform_data_interface_type_to_null_transform, transform_data_null_to_interface_type_transform, true, true},

	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/mtu", "network.%s.mtu", NULL, NULL, NULL, NULL, false, false},
	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/enabled", "network.%s.enabled", NULL,
	 NULL, transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},

	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/mtu", "network.%s.mtu", NULL, NULL, NULL, NULL, false, false},
	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/enabled", "network.%s.enabled", NULL,
	 NULL, transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},

	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/address[ip='%s']/ip", "network.%s.ipaddr", NULL,
	 transform_path_address_cb, NULL, NULL, false, false},
	/* netmask leaf is dependent on the `ipv4-non-contiguous-netmasks` feature */
	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/address[ip='%s']/prefix-length", "network.%s.netmask", NULL,
	 transform_path_address_cb,
	 transform_data_ipv4_prefixlen_to_netmask_transform, transform_data_ipv4_netmask_to_prefixlen_transform, true, true},
	{INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv4/address[ip='%s']/prefix-length", "network.%s.ip4prefixlen", NULL,
	 transform_path_address_cb, NULL, NULL, false, false},

	// {INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/address[ip='%s']/ip", "network.%s.ip6addr", NULL,
	//  transform_path_address_cb, transform_data_ipv6_add_prefixlen_transform, transform_data_ipv6_strip_prefixlen_transform, true, true},
	// {INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/address[ip='%s']/prefix-length", "network.%s.ip6addr", NULL,
	//  transform_path_address_cb, transform_data_ipv6_add_ip_transform, transform_data_ipv6_strip_ip_transform, true, true},
	// {INTERFACE_XPATH_TEMPLATE "/ietf-ip:ipv6/address[ip='%s']/prefix-length", "network.%s.ip6prefixlen", NULL,
	//  transform_path_address_cb, NULL, NULL, false, false},
};

static const char *network_uci_sections[] = {"interface"};

static struct {
	const char *uci_file;
	const char **uci_section_list;
	size_t uci_section_list_size;
} network_config_files[] = {
	{"network", network_uci_sections, ARRAY_SIZE(network_uci_sections)},
};

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
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
	error = sr_module_change_subscribe(session, NETWORK_YANG_MODEL, "/" NETWORK_YANG_MODEL ":*//*",
									   network_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, NETWORK_YANG_MODEL, INTERFACES_STATE_YANG_PATH,
										network_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
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

	for (size_t i = 0; i < ARRAY_SIZE(network_config_files); i++) {
		error = srpo_uci_ucipath_list_get(network_config_files[i].uci_file,
										  network_config_files[i].uci_section_list,
										  network_config_files[i].uci_section_list_size,
										  &uci_path_list, &uci_path_list_size, true);
		if (error) {
			SRP_LOG_ERR("srpo_uci_path_list_get error (%d): %s", error, srpo_uci_error_description_get(error));
			goto error_out;
		}

		for (size_t j = 0; j < uci_path_list_size; j++) {
			error = srpo_uci_ucipath_to_xpath_convert(uci_path_list[j], network_xpath_uci_path_template_map,
													  ARRAY_SIZE(network_xpath_uci_path_template_map), &xpath);
			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_to_xpath_path_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				FREE_SAFE(uci_path_list[j]);
				continue;
			}

			error = srpo_uci_transform_uci_data_cb_get(uci_path_list[j], network_xpath_uci_path_template_map,
													   ARRAY_SIZE(network_xpath_uci_path_template_map),
													   &transform_uci_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_uci_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_uci_data_private_get(uci_path_list[j], network_xpath_uci_path_template_map,
																ARRAY_SIZE(network_xpath_uci_path_template_map),
																&has_transform_uci_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_uci_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path_list[j]);

			error = srpo_uci_element_value_get(uci_path_list[j], transform_uci_data_cb,
											   has_transform_uci_data_private ? uci_section_name : NULL,
											   &uci_value_list, &uci_value_list_size);
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

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	srpo_uci_cleanup();

	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int network_module_change_cb(sr_session_ctx_t *session, const char *module_name,
									const char *xpath, sr_event_t event, uint32_t request_id,
									void *private_data)
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

		while (sr_get_change_tree_next(session, network_server_change_iter, &operation, &node,
									   &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = network_xpath_get(node);

			error = srpo_uci_xpath_to_ucipath_convert(node_xpath,
													  network_xpath_uci_path_template_map,
													  ARRAY_SIZE(network_xpath_uci_path_template_map),
													  &uci_path);
			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_xpath_to_ucipath_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				error = 0;
				SRP_LOG_DBG("xpath %s not found in table", node_xpath);
				FREE_SAFE(node_xpath);
				continue;
			}

			error = srpo_uci_transform_sysrepo_data_cb_get(node_xpath,
														   network_xpath_uci_path_template_map,
														   ARRAY_SIZE(network_xpath_uci_path_template_map),
														   &transform_sysrepo_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_sysrepo_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_sysrepo_data_private_get(node_xpath,
																	network_xpath_uci_path_template_map,
																	ARRAY_SIZE(network_xpath_uci_path_template_map),
																	&has_transform_sysrepo_data_private);
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
					if (has_transform_sysrepo_data_private) {
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

static int network_state_data_cb(sr_session_ctx_t *session, const char *module_name,
								 const char *path, const char *request_xpath, uint32_t request_id,
								 struct lyd_node **parent, void *private_data)
{
	return SR_ERR_CALLBACK_FAILED;
}

static int transform_path_address_cb(const char *target, const char *from, const char *to,
									 srpo_uci_path_direction_t direction, char **path)
{
	int error = SRPO_UCI_ERR_ARGUMENT;
	char *path_key_value = NULL;
	char **uci_value_list = NULL;
	size_t uci_value_list_size = 0;
	char *ipaddr_uci_key = NULL;
	size_t ipaddr_uci_key_size = 0;
	char *path_tmp = NULL;
	size_t path_tmp_size = 0;
	const char *ipaddr_template = NULL;

	if (from == NULL || to == NULL)
		goto cleanup;

	if (direction == SRPO_UCI_PATH_DIRECTION_UCI) {
		path_key_value = srpo_uci_xpath_key_value_get(target, 1);
		ipaddr_uci_key = srpo_uci_xpath_key_value_get(target, 2);

		path_tmp_size = (strlen(from) - 4 + 1) + strlen(path_key_value) + strlen(ipaddr_uci_key);
		path_tmp = xmalloc(path_tmp_size);
		snprintf(path_tmp, path_tmp_size, from, path_key_value, ipaddr_uci_key);

		if (strcmp(target, path_tmp) != 0) {
			error = SRPO_UCI_ERR_NOT_FOUND;
			goto cleanup;
		}

		FREE_SAFE(path_tmp);
		path_tmp = NULL;
		path_tmp_size = 0;

		path_tmp_size = (strlen(to) - 2 + 1) + strlen(path_key_value);
		path_tmp = xmalloc(path_tmp_size);
		snprintf(path_tmp, path_tmp_size, to, path_key_value);

		*path = xstrdup(path_tmp);

		error = SRPO_UCI_ERR_OK;
		goto cleanup;
	} else if (direction == SRPO_UCI_PATH_DIRECTION_XPATH) {
		path_key_value = srpo_uci_section_name_get(target);

		path_tmp_size = (strlen(from) - 2 + 1) + strlen(path_key_value);
		path_tmp = xmalloc(path_tmp_size);
		snprintf(path_tmp, path_tmp_size, from, path_key_value);

		if (strcmp(target, path_tmp) != 0) {
			error = SRPO_UCI_ERR_NOT_FOUND;
			goto cleanup;
		}

		FREE_SAFE(path_tmp);
		path_tmp = NULL;
		path_tmp_size = 0;

		ipaddr_template = strstr(to, "ipv6") != NULL ? IP6ADDR_UCI_TEMPLATE : IPADDR_UCI_TEMPLATE;

		ipaddr_uci_key_size = (strlen(ipaddr_template) - 2 + 1) + strlen(path_key_value);
		ipaddr_uci_key = xmalloc(ipaddr_uci_key_size);
		snprintf(ipaddr_uci_key, ipaddr_uci_key_size, IPADDR_UCI_TEMPLATE, path_key_value);

		error = srpo_uci_element_value_get(ipaddr_uci_key, NULL, NULL, &uci_value_list, &uci_value_list_size);
		if (error || uci_value_list_size != 1) {
			error = SRPO_UCI_ERR_UCI;
			goto cleanup;
		}

		FREE_SAFE(ipaddr_uci_key);
		ipaddr_uci_key = xstrdup(uci_value_list[0]);

		path_tmp_size = (strlen(to) - 2 + 1) + strlen(path_key_value) + strlen(ipaddr_uci_key);
		path_tmp = xmalloc(path_tmp_size);
		snprintf(path_tmp, path_tmp_size, to, path_key_value, ipaddr_uci_key);

		*path = xstrdup(path_tmp);

		error = SRPO_UCI_ERR_OK;
		goto cleanup;
	} else {
		error = SRPO_UCI_ERR_ARGUMENT;
		goto cleanup;
	}

	error = SRPO_UCI_ERR_NOT_FOUND;

cleanup:
	for (size_t i = 0; i < uci_value_list_size; i++) {
		FREE_SAFE(uci_value_list[i]);
	}
	FREE_SAFE(uci_value_list);

	FREE_SAFE(ipaddr_uci_key);
	FREE_SAFE(path_key_value);
	FREE_SAFE(path_tmp);

	return error;
}

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath,
										  srpo_ubus_result_values_t *values, struct lyd_node **parent)
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

	error = sr_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("sr_plugin_init_cb error");
		goto out;
	}

	/*  loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);
	}

out:
	sr_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
