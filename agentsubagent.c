#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "agentsubagent.h"

/* Base OID */
static oid *base_oid = NULL;
static size_t base_oid_length = 0;
static oid default_base_oid[] =
    { 1, 3, 6, 1, 4, 1, 8072, 2, 1, 2, 0 };

int
compare_oids(oid *oid1, size_t oid1_len, oid *oid2, size_t oid2_len){
    size_t i;
    for(i = 0; (i < oid1_len && i < oid2_len); i++){
        if(oid1[i] != oid2[i]){
            return ((oid1[i] > oid2[i]) ? 1 : -1);
        }
    }
    if(oid1_len != oid2_len){
        return ((oid1_len > oid2_len) ? 1 : -1);
    }
    return 0;
}

struct snmpdata *
getnext(oid *myoid, int *myoid_len)
{
    int found=0, i;
    char myoid_string[100];
    struct snmpdata *d;
    oid *oid_suffix;

    // skip base oid sequence, compare suffixes only
    oid_suffix = myoid;
    oid_suffix += base_oid_length;

    LOCK_READ(&head_lock);
    LIST_FOREACH(d, &head, next) {
	if(compare_oids(d->octet, d->octet_len, oid_suffix, *myoid_len - base_oid_length) > 0) {
	    found = 1;
	    break;
	}
    }
    UNLOCK(&head_lock);
    if(!found){
        snprint_objid(myoid_string, 100, myoid, *myoid_len);
	DEBUGMSGTL(("agentsubagent", "(getnext) Next OID for %s not found\n", myoid_string));
	return NULL;
    }

    for(i = 0; i < d->octet_len; i++){
        myoid[base_oid_length + i] = d->octet[i];
    }
    *myoid_len = base_oid_length + d->octet_len;
    snprint_objid(myoid_string, 100, myoid, *myoid_len);
    DEBUGMSGTL(("agentsubagent", "(getnext) Next OID is %s\n", myoid_string));
    
    return d;
}

int
instance_handler(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    char oid_string[100];
    struct snmpdata *d;
    oid myoid[MAX_OID_LEN];
    int myoid_len=0;
    int l=0;
    netsnmp_request_info *r;

    snprint_objid(oid_string, 100, requests->requestvb->name, requests->requestvb->name_length);

    DEBUGMSGTL(("agentsubagent", "Got request for %s (%u), mode = %u:\n",
                oid_string, (u_int)requests->requestvb->name_length, reqinfo->mode));

    switch (reqinfo->mode) {
        /*
         * registering as an instance means we don't need to deal with
         * getnext processing, so we don't handle it here at all.
         * 
         * However, since the instance handler already reset the mode
         * back to GETNEXT from the faked GET mode, we need to do the
         * same thing in both cases.  This should be fixed in future
         * versions of net-snmp hopefully. 
         */

    case MODE_GET:
	LOCK_READ(&head_lock);
	for(r = requests; r; r = r->next) {
	    snprint_objid(oid_string, 100, r->requestvb->name, r->requestvb->name_length);
	    DEBUGMSGTL(("agentsubagent", "GET OID: %s\n", oid_string));
	    LIST_FOREACH(d, &head, next) {
		if(compare_oids(d->octet, d->octet_len, &(r->requestvb->name[base_oid_length]), r->requestvb->name_length - base_oid_length) == 0){
		    snmp_set_var_typed_value(r->requestvb,
					     d->type,
					     (u_char *)d->value,
					     d->value_size);
		    break;
		}
	    }
	}
	UNLOCK(&head_lock);
        break;
    case MODE_GETNEXT:
//    case MODE_GETBULK:
	for(r = requests; r; r = r->next) {
	    memcpy(myoid, r->requestvb->name, r->requestvb->name_length*sizeof(oid));
	    myoid_len = r->requestvb->name_length;
	    d = getnext(myoid, &myoid_len);
	    if(d) {
		snmp_set_var_typed_value(r->requestvb,
					 d->type,
					 (u_char *)d->value,
					 d->value_size);
		
		snmp_set_var_objid(r->requestvb, myoid, myoid_len);
		snprint_objid(oid_string, 100, myoid, myoid_len);
		DEBUGMSGTL(("agentsubagent", "Next OID: %s\n", oid_string));
	    } else {
		snmp_set_var_typed_value(r->requestvb,
					 ASN_INTEGER,
					 (u_char *)&l,
					 sizeof(l));
                netsnmp_set_request_error(reqinfo, requests, SNMP_ENDOFMIBVIEW);
		DEBUGMSGTL(("agentsubagent", "Next OID not found, pushing out of base oid (%s)\n", oid_string));
		}
	}
	break;
    default:
        DEBUGMSGTL(("agentsubagent", "Unsupported request mode = %d:\n", reqinfo->mode));
                        
    }
    DEBUGMSGTL(("agentsubagent", "---\n"));
    return SNMP_ERR_NOERROR;
}

/*
 * our initialization routine, automatically called by the agent 
 * (to get called, the function name must match init_FILENAME()) 
 */
void
init_agentsubagent(oid *_base_oid, size_t _base_oid_length)
{
    char oid_string[100];
    
    netsnmp_handler_registration *reg;

    DEBUGMSGTL(("agentsubagent",
                "Initializing the agentsubagent module\n"));

    base_oid = _base_oid;
    base_oid_length = _base_oid_length;
    
    if (base_oid == NULL){
      base_oid = default_base_oid;
      base_oid_length = OID_LENGTH(default_base_oid);
      DEBUGMSGTL(("agentsubagent", "No base OID supplied from command line, using default.\n"));
    }
    
    snprint_objid(oid_string, 100, base_oid, base_oid_length);
    DEBUGMSGTL(("agentsubagent", "Registering at OID %s\n", oid_string));

    reg =
        netsnmp_create_handler_registration("agentsubagent",
                                            instance_handler,
                                            base_oid,
                                            base_oid_length,
                                            HANDLER_CAN_RONLY);

    netsnmp_register_handler(reg);

    DEBUGMSGTL(("agentsubagent",
                "Done initalizing agentsubagent module\n"));
}

