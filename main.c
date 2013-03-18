#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "agentsubagent.h"

#define DATA_FILE "/var/spool/snmp/snmp.data"

#define SELECT_TIMEOUT_US 500000

static int keep_running;
static int debug;

static struct _s_x {
    char const *s;
    u_char	type;
} types_list[] = {
    { "COUNTER",	ASN_COUNTER },
    { "COUNTER64",	ASN_COUNTER64 },
    { "INTEGER",	ASN_INTEGER },
    { "STRING",		ASN_OCTET_STR },
    { NULL, 0 }
};

RETSIGTYPE
stop_server(int a) {
    keep_running = 0;
}

int
only_digits(char *str)
{
    int i, len=strlen(str);

    for(i=0; i<len; i++)
	if(!isdigit(str[i]))
	    return 0;
    return 1;
}

int
parse_line(char *str, struct snmpdata *data, int line)
{
    char *p, *p1, *p2;
    int i=0, found=0;
    long long tll;
    struct counter64 *tc64;

    p = str;
    p1 = strsep(&p, " \t");
    
    data->octet_len = 0;
    for(p2 = str; (p2 = strsep(&p1, ".")) != NULL; ){
        if(data->octet_len == MAX_SUBAGENT_OID_LENGTH){
            snmp_log(LOG_ERR, "Index error in line: %d - too many suffix oids. Ignored.\n", line);
            return 0;
        }
        if(!only_digits(p2)){
    	    snmp_log(LOG_ERR, "Index error in line: %d. Ignored.\n", line);
    	    return 0;
        }
        data->octet[data->octet_len] = strtol(p2, NULL, 10);
        data->octet_len++;
    }
    i = 0;

    p1 = strsep(&p, " \t");
    while(types_list[i].s != NULL) {
	if(strcmp(types_list[i].s, p1) == 0) {
	    data->type = types_list[i].type;
	    found=1;
	    break;
	}
	i++;
    }
    if(!found) {
	snmp_log(LOG_ERR, "Unknown type name. Line: %d. Ignored.\n", line);
	return 0;
    }

    p1 = p;
    /* XXX error checking */
    switch(data->type) {
	case ASN_INTEGER:
	case ASN_COUNTER:
	    data->value = malloc(sizeof(long));
	    *((long*)data->value) = strtol(p1, NULL, 10);
	    data->value_size = sizeof(long);
	    break;
	case ASN_COUNTER64:
	    data->value = malloc(sizeof(struct counter64));
	    tc64 = (struct counter64 *)(data->value);
	    tll = strtoll(p1, NULL, 10);
	    tc64->low = tll&0xFFFFFFFFLL;
	    tc64->high = tll>>32;
	    data->value_size = sizeof(sizeof(struct counter64));
	    break;
	case ASN_OCTET_STR:
	    p = p1 + strlen(p1);
	    p--;
	    if(*p1 != '"' || *(p-1) != '"') {
		snmp_log(LOG_ERR, "String format error. Line: %d. Ignored.\n", line);
		return 0;
	    }
	    p1++; p--; *p='\0';
	    data->value = malloc(p-p1+1);
	    data->value_size = p-p1;
	    strcpy(data->value, p1);
	    break;
	default:
	    snmp_log(LOG_ERR, "Internal: unknown type. Line: %d. Ignored.\n", line);
	    return 0;
    }
    return 1;
}

void
print_data()
{
    struct snmpdata *d;
    int i;
    char buf[I64CHARSZ+1];

    printf("--start--\n");

    LIST_FOREACH(d, &head, next) {
	for(i=0; i < d->octet_len; i++){
    	    printf("%lu", d->octet[i]);
    	    if( i < (d->octet_len - 1) ){
    	        printf(".");
    	    }
	}
	printf(" ");
	i=0;
	while(types_list[i].s != NULL) {
	    if(types_list[i].type == d->type)
		break;
	    i++;
	}
	printf("%s ", types_list[i].s);
	switch(d->type) {
	    case ASN_INTEGER:
		printf("%ld ", *((long*)d->value));
		break;
	    case ASN_COUNTER:
		printf("%lu ", *((u_long*)d->value));
		break;
	    case ASN_COUNTER64:
		printU64(buf, (const U64*)d->value);
		printf("%s ", buf);
		break;
	    case ASN_OCTET_STR:
		printf("%s ", (char*)d->value);
		break;
	    default:
		printf("Internal: unknown type\n");
	}
	printf("\n");
    }
    printf("--stop--\n");
}

void
read_file(char *file, time_t *mtime) {
    FILE *f;
    char str[200];
    int line=1, found;
    struct stat sb;
    struct snmpdata *data, *d, *last_data=NULL;
    LIST_HEAD(list_head, snmpdata) read_head, temp_head;

    *mtime = 0;

    if((f = fopen(file, "r")) == NULL) {
	snmp_log(LOG_ERR, "Can't open file %s: %s\n", file, strerror(errno));
	if(debug)
	    printf("Can't open file %s: %s\n", file, strerror(errno));
	    
	return;
    }
    
    if(flock(fileno(f), LOCK_EX|LOCK_NB) < 0) {
        if(errno != EWOULDBLOCK && debug)
            printf("Lock failed: %s(%d)\n", strerror(errno), errno);
        fclose(f);
        return;
    }

    LIST_INIT(&read_head);

    while(fgets(str, sizeof(str)-1, f) != NULL) {
	data = malloc(sizeof(struct snmpdata));
	if(data == NULL)
	    errx(1, "malloc()");
	if(parse_line(str, data, line)) {
	    found=0;
	    if(LIST_EMPTY(&read_head)) {
		LIST_INSERT_HEAD(&read_head, data, next);
		found=1;
	    } else {
		LIST_FOREACH(d, &read_head, next) {
		    if(compare_oids(d->octet, d->octet_len, data->octet, data->octet_len) == 0){
			snmp_log(LOG_ERR, "Duplicate index at line: %d. Ignored.", line);
			free(data);
			goto next_line;
		    }
		    if(compare_oids(d->octet, d->octet_len, data->octet, data->octet_len) > 0){
			LIST_INSERT_BEFORE(d, data, next);
			found=1;
			break;
		    }
		    last_data = d;
		}
	    }
	    if(!found)
		LIST_INSERT_AFTER(last_data, data, next);
	} else
	    free(data);
next_line:
	line++;
    }

    LIST_FIRST(&temp_head) = LIST_FIRST(&head);

    LOCK_WRITE(&head_lock);
    LIST_FIRST(&head) = LIST_FIRST(&read_head);
    UNLOCK(&head_lock);

    /* Delete old list */
    data = LIST_FIRST(&temp_head);
    while(data != NULL) {
	d = LIST_NEXT(data, next);
	free(data->value);
	free(data);
	data = d;
    }
    flock(fileno(f), LOCK_UN);
    fclose(f);
    stat(file, &sb);
    *mtime = sb.st_mtime;
    if(debug)
	print_data();
}

int
snmpdatad_check_and_process(suseconds_t us_sleep)
{
    int             numfds;
    fd_set          fdset;
    struct timeval  timeout = { 0, 0 }, *tvp = &timeout;
    int             count;
    int             fakeblock = 0;


    timeout.tv_usec = us_sleep;
    numfds = 0;
    FD_ZERO(&fdset);
    snmp_select_info(&numfds, &fdset, tvp, &fakeblock);

    count = select(numfds, &fdset, NULL, NULL, tvp);

    if (count > 0) {
        /*
         * packets found, process them 
         */
        snmp_read(&fdset);
    } else
        switch (count) {
        case 0:
            snmp_timeout();
            break;
        case -1:
            if (errno != EINTR) {
                snmp_log_perror("select");
            }
            return -1;
        default:
            snmp_log(LOG_ERR, "select returned %d\n", count);
            return -1;
        }                       /* endif -- count>0 */

    /*
     * Run requested alarms.  
     */
    run_alarms();

    netsnmp_check_outstanding_agent_requests();

    return count;
}

int
main (int argc, char **argv) {
    int background=1, slog=1, i=0, j, queries=0, force_read_file_counter=0;
    char file[256], str[256], c;
    struct stat sb;
    time_t last_changed_time;
    static oid *base_oid = NULL;
    int raw_base_oid[MAX_OID_LEN];
    char *pch;
    size_t oid_length = 0;

    strncpy(file, DATA_FILE, sizeof(file));
    while ((c = getopt(argc, argv, "df:b:")) != -1) {
        switch (c) {
	    case 'd':
	        debug = 1;
	        background = 0;
	        slog = 0;
	        break;
            case 'f':
                strncpy(file, optarg, sizeof(file));
                break;
            case 'b':
                for (i = 0; i < MAX_OID_LEN; i++){
                  raw_base_oid[i] = -1;
                }
		strncpy(str, optarg, sizeof(str)-1);
		pch = strtok (str,".");
                i = 0;
		while (pch != NULL)
		{
		    sscanf(pch, "%d", &(raw_base_oid[i++]));
		    pch = strtok (NULL, ".");
		}                
		if (i < 6){
		    errx(1, "Too short base OID: %d < 6", i);
		}
		base_oid = (oid *)malloc(i*sizeof(oid));
                if(base_oid == NULL){
                    errx(1, "malloc: could not allocate base_oid array containing %d items", i);
                }
                oid_length = i;
                for( j = 0; j < oid_length; j++){
                    if (raw_base_oid[j] == -1){
                        break;
                    }
                    base_oid[j] = (oid)raw_base_oid[j];
                }
                break;
	    default:
	        errx(1, "Unknown option: -%c", c);
        }
    }

    // use numeric OIDs
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
                                                        NETSNMP_OID_OUTPUT_NUMERIC);

    netsnmp_ds_toggle_boolean(NETSNMP_DS_APPLICATION_ID,
                                                        NETSNMP_DS_AGENT_NO_ROOT_ACCESS);
                                                      

    if(stat(file, &sb) < 0) {
        if(errno == ENOENT) {
            errx(1, "Not found: %s", file);
        } else
	    errx(1, "Unknown stat() error for %s", file);
    }

    if(slog) {
	snmp_enable_calllog();
    } else
        snmp_enable_stderrlog();

    if(debug)
        snmp_set_do_debugging(1);

    debug_register_tokens("agentsubagent");

    /* print log errors to syslog or stderr */
    /* make us a agentx client. */
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);

    /* run in background, if requested */
    if (background && netsnmp_daemonize(1, !slog))
        exit(1);

    /* initialize tcpip, if necessary */
    SOCK_STARTUP;

    /* initialize the agent library */
    init_agent("snmpdatad");

    /* initialize mib code here */

    /* mib code: init_agentsubagent from agentsubagent.c */
    init_agentsubagent(base_oid, oid_length);

    /* snmpdatad will be used to read example-demon.conf files. */
    init_snmp("snmpdatad");

    /* In case we recevie a request to stop (kill -TERM or kill -INT) */
    keep_running = 1;
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);

    snmp_log(LOG_INFO,"snmpdatad is up and running.\n");

    LIST_INIT(&head);
    read_file(file, &last_changed_time);

    LOCK_INIT(&head_lock);

    /* your main loop here... */
    while(keep_running) {
        if (stat(file, &sb) < 0) { /* check file each second */
            /*snmp_log(LOG_ERR, "Can't find file %s\n", file);*/
        } else
        if(sb.st_mtime > last_changed_time){
            force_read_file_counter++;
            if (queries == 0 || force_read_file_counter >= 10){ /* if we have no queries last poll or we are forced to re-read it due to time lag*/
                read_file(file, &last_changed_time);
                force_read_file_counter = 0;
            }
        }
        queries = snmpdatad_check_and_process(SELECT_TIMEOUT_US);
    }

    /* at shutdown time */
    snmp_shutdown("snmpdatad");
    if (base_oid != NULL){
        free(base_oid);
    }
    SOCK_CLEANUP;
    LOCK_DESTROY(&head_lock);
    
    return 0;
}
