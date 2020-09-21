#include <inttypes.h>
#include <string.h>

#include <uci.h>
#include <arpa/inet.h>

#include "transform_data.h"
#include "utils/memory.h"

char *transform_data_boolean_to_zero_one_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0)
		return xstrdup("1");

	return xstrdup("0");
}

char *transform_data_zero_one_to_boolean_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("true");

	return xstrdup("false");
}

char *transform_data_boolean_to_zero_one_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0)
		return xstrdup("0");

	return xstrdup("1");
}

char *transform_data_zero_one_to_boolean_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("false");

	return xstrdup("true");
}

char *transform_data_null_to_interface_type_transform(const char *value, void *private_data)
{
	return xstrdup("iana-if-type:ethernetCsmacd");
}

char *transform_data_interface_type_to_null_transform(const char *value, void *private_data)
{
	return NULL;
}

char *transform_data_ipv4_netmask_to_prefixlen_transform(const char *value, void *private_data)
{
	struct in_addr addr;
	char *str = NULL;
	uint32_t mask;
	uint32_t n = 0;

	if (inet_pton(AF_INET, value, &addr) <= 0)
		return NULL;

	mask = ntohl(addr.s_addr);
	while ((mask & ((uint32_t) 1 << ((uint32_t) 31 - n))) != 0) {
		if (n > 31)
			break;

		n++;
	}

	str = xmalloc(sizeof(uint32_t) + 1);
	if (str == NULL)
		return NULL;

	sprintf(str, "%" PRIu32, n);
	transform_data_ipv4_prefixlen_to_netmask_transform((const char *) str, NULL);

	return str;
}

char *transform_data_ipv4_prefixlen_to_netmask_transform(const char *value, void *private_data)
{
	struct in_addr addr;
	uint32_t mask, n = 0;
	char *str = NULL;

	sscanf(value, "%" SCNu32, &mask);
	for (uint32_t i = 0; i < mask; i++) {
		n |= (uint32_t) 1 << ((uint32_t) 31 - i);
	}

	addr.s_addr = htonl(n);

	str = xmalloc(INET_ADDRSTRLEN + 1);
	if (!str)
		return NULL;

	if (inet_ntop(AF_INET, &(addr.s_addr), str, INET_ADDRSTRLEN) == NULL)
		return NULL;

	return str;
}

/*
char *transform_data_ipv6_strip_prefixlen_transform(const char *value, void *private_data)
{
	char *string = NULL;
	char *string_pos = NULL;
	char *without = NULL;

	string = xstrdup(value);
	string_pos = strrchr(string, '/');
	if (string_pos == NULL)
		return NULL;

	*string_pos = '\0';
	without = xstrdup(string);

	FREE_SAFE(string);
	string = NULL;

	return without;
}

char *transform_data_ipv6_add_prefixlen_transform(const char *value, void *private_data)
{
	return NULL;
}

char *transform_data_ipv6_strip_ip_transform(const char *value, void *private_data)
{
	char *string = NULL;
	char *string_pos = NULL;
	char *without = NULL;

	string = xstrdup(value);
	string_pos = strrchr(string, '/');
	if (string_pos == NULL)
		return NULL;

	*string_pos = '\0';
	without = xstrdup(string_pos);

	FREE_SAFE(string);
	string = NULL;

	return without;
}

char *transform_data_ipv6_add_ip_transform(const char *value, void *private_data)
{
	return NULL;
}
*/