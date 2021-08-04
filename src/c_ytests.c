/***********************************************************************
 *          C_YTESTS.C
 *          YTests GClass.
 *
 *          Yuneta Tests
 *
 *          Copyright (c) 2016 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "c_ytests.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE int extrae_json(hgobj gobj);
PRIVATE int cmd_connect(hgobj gobj);


/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/


PRIVATE sdata_desc_t commands_desc[] = {
/*-ATTR-type------------name----------------flag----default-----description---------- */
SDATA (ASN_OCTET_STR,   "command",          0,      0,          "command"),
SDATA (ASN_OCTET_STR,   "date",             0,      0,          "date of command"),
SDATA (ASN_JSON,        "kw",               0,      0,          "kw"),
SDATA (ASN_JSON,        "response",         0,      0,          "Keys to validate the response"),
SDATA (ASN_JSON,        "filter",           0,      0,          "Filter response"),
SDATA (ASN_BOOLEAN,     "ignore_fail",      0,      0,          "continue tests although fail"),
SDATA (ASN_BOOLEAN,     "without_metadata", 0,      0,          ""),
SDATA (ASN_BOOLEAN,     "without_private",  0,      0,          ""),

SDATA_END()
};

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag------------------------default---------description---------- */
SDATA (ASN_INTEGER,     "verbose",          0,                          0,              "Verbose mode."),
SDATA (ASN_OCTET_STR,   "path",             0,                          0,              "Tests filename to execute."),
SDATA (ASN_INTEGER,     "repeat",           0,                          1,              "Repeat the execution of the tests. -1 infinite"),
SDATA (ASN_INTEGER,     "pause",            0,                          0,              "Pause between executions"),

SDATA (ASN_OCTET_STR,   "jwt",              0,          "",             "Jwt"),
SDATA (ASN_OCTET_STR,   "url",              0,                          "ws://127.0.0.1:1991",  "Agent's url to connect. Can be a ip/hostname or a full url"),
SDATA (ASN_OCTET_STR,   "yuno_name",        0,                          "",             "Yuno name"),
SDATA (ASN_OCTET_STR,   "yuno_role",        0,                          "yuneta_agent", "Yuno role"),
SDATA (ASN_OCTET_STR,   "yuno_service",     0,                          "agent",        "Yuno service"),
SDATA (ASN_OCTET_STR,   "display_mode",     0,                          "form",         "Display mode: table or form"),

SDATA (ASN_INTEGER,     "timeout",          0,                          60*1000,        "Timeout service responses"),
SDATA (ASN_POINTER,     "user_data",        0,                          0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,                          0,              "more user data"),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_USER = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"trace_user",        "Trace user description"},
{0, 0},
};


/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t timeout;
    int32_t pause;
    int32_t repeat;
    int verbose;
    const char *path;
    hgobj timer;
    hgobj remote_service;
    dl_list_t tests_iter;

    hsdata hs;
    rc_instance_t *i_hs;

} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    priv->timer = gobj_create("", GCLASS_TIMER, 0, gobj);
    rc_init_iter(&priv->tests_iter);

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timeout,               gobj_read_int32_attr)
    SET_PRIV(pause,                 gobj_read_int32_attr)
    SET_PRIV(verbose,               gobj_read_int32_attr)
    SET_PRIV(repeat,                gobj_read_int32_attr)
    SET_PRIV(path,                  gobj_read_str_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(timeout,             gobj_read_int32_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    rc_free_iter(&priv->tests_iter, FALSE, sdata_destroy);
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    extrae_json(gobj);
    gobj_start(priv->timer);

    cmd_connect(gobj);

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    clear_timeout(priv->timer);
    gobj_stop(priv->timer);
    return 0;
}




            /***************************
             *      Commands
             ***************************/




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int extrae_json(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  Open commands file
     */
    FILE *file = fopen(priv->path, "r");
    if(!file) {
        printf("ytests: cannot open '%s' file\n", priv->path);
        exit(-1);
    }

    /*
     *  Load commands
     */
    #define WAIT_BEGIN_DICT 0
    #define WAIT_END_DICT   1
    int c;
    int st = WAIT_BEGIN_DICT;
    int brace_indent = 0;
    GBUFFER *gbuf = gbuf_create(4*1024, gbmem_get_maximum_block(), 0, 0);
    while((c=fgetc(file))!=EOF) {
        switch(st) {
        case WAIT_BEGIN_DICT:
            if(c != '{') {
                continue;
            }
            gbuf_reset_wr(gbuf);
            gbuf_reset_rd(gbuf);
            gbuf_append(gbuf, &c, 1);
            brace_indent = 1;
            st = WAIT_END_DICT;
            break;
        case WAIT_END_DICT:
            if(c == '{') {
                brace_indent++;
            } else if(c == '}') {
                brace_indent--;
            }
            gbuf_append(gbuf, &c, 1);
            if(brace_indent == 0) {
                //log_debug_gbuf("TEST", gbuf);
                json_t *jn_dict = legalstring2json(gbuf_cur_rd_pointer(gbuf), TRUE);
                if(jn_dict) {
                    if(kw_get_str(jn_dict, "command", 0, 0)) {
                        hsdata hs_cmd = sdata_create(commands_desc, 0, 0, 0, 0, 0);
                        json2sdata(hs_cmd, jn_dict, -1, 0, 0); // TODO inform attr not found
                        const char *command = sdata_read_str(hs_cmd, "command");
                        if(command && (*command == '-')) {
                            sdata_write_str(hs_cmd, "command", command+1);
                            sdata_write_bool(hs_cmd, "ignore_fail", TRUE);
                        }
                        rc_add_instance(&priv->tests_iter, hs_cmd, 0);
                    } else {
                        printf("Line ignored: '%s'\n", (char *)gbuf_cur_rd_pointer(gbuf));
                    }
                    json_decref(jn_dict);
                } else {
                    log_error(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_SERVICE_ERROR,
                        "msg",          "%s", "Error json",
                        NULL
                    );
                    //log_debug_gbuf("FAILED", gbuf);
                }
                st = WAIT_BEGIN_DICT;
            }
            break;
        }
    }
    fclose(file);
    gbuf_decref(gbuf);

    //log_debug_sd_iter("TEST", 0, &priv->tests_iter);

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE char agent_insecure_config[]= "\
{                                               \n\
    'name': '(^^__url__^^)',                    \n\
    'gclass': 'IEvent_cli',                     \n\
    'as_unique': true,                          \n\
    'kw': {                                     \n\
        'remote_yuno_name': '(^^__yuno_name__^^)',      \n\
        'remote_yuno_role': '(^^__yuno_role__^^)',      \n\
        'remote_yuno_service': '(^^__yuno_service__^^)' \n\
    },                                          \n\
    'zchilds': [                                 \n\
        {                                               \n\
            'name': '(^^__url__^^)',                    \n\
            'gclass': 'IOGate',                         \n\
            'kw': {                                     \n\
            },                                          \n\
            'zchilds': [                                 \n\
                {                                               \n\
                    'name': '(^^__url__^^)',                    \n\
                    'gclass': 'Channel',                        \n\
                    'kw': {                                     \n\
                    },                                          \n\
                    'zchilds': [                                 \n\
                        {                                               \n\
                            'name': '(^^__url__^^)',                    \n\
                            'gclass': 'GWebSocket',                     \n\
                            'zchilds': [                                \n\
                                {                                       \n\
                                    'name': '(^^__url__^^)',            \n\
                                    'gclass': 'Connex',                 \n\
                                    'kw': {                             \n\
                                        'urls':[                        \n\
                                            '(^^__url__^^)'             \n\
                                        ]                               \n\
                                    }                                   \n\
                                }                                       \n\
                            ]                                           \n\
                        }                                               \n\
                    ]                                           \n\
                }                                               \n\
            ]                                           \n\
        }                                               \n\
    ]                                           \n\
}                                               \n\
";

PRIVATE char agent_secure_config[]= "\
{                                               \n\
    'name': '(^^__url__^^)',                    \n\
    'gclass': 'IEvent_cli',                     \n\
    'as_unique': true,                          \n\
    'kw': {                                     \n\
        'jwt': '(^^__jwt__^^)',                         \n\
        'remote_yuno_name': '(^^__yuno_name__^^)',      \n\
        'remote_yuno_role': '(^^__yuno_role__^^)',      \n\
        'remote_yuno_service': '(^^__yuno_service__^^)' \n\
    },                                          \n\
    'zchilds': [                                 \n\
        {                                               \n\
            'name': '(^^__url__^^)',                    \n\
            'gclass': 'IOGate',                         \n\
            'kw': {                                     \n\
            },                                          \n\
            'zchilds': [                                 \n\
                {                                               \n\
                    'name': '(^^__url__^^)',                    \n\
                    'gclass': 'Channel',                        \n\
                    'kw': {                                     \n\
                    },                                          \n\
                    'zchilds': [                                 \n\
                        {                                               \n\
                            'name': '(^^__url__^^)',                    \n\
                            'gclass': 'GWebSocket',                     \n\
                            'zchilds': [                                \n\
                                {                                       \n\
                                    'name': '(^^__url__^^)',            \n\
                                    'gclass': 'Connexs',                \n\
                                    'kw': {                             \n\
                                        'crypto': {                     \n\
                                            'library': 'openssl',       \n\
                                            'trace': false              \n\
                                        },                              \n\
                                        'urls':[                        \n\
                                            '(^^__url__^^)'             \n\
                                        ]                               \n\
                                    }                                   \n\
                                }                                       \n\
                            ]                                           \n\
                        }                                               \n\
                    ]                                           \n\
                }                                               \n\
            ]                                           \n\
        }                                               \n\
    ]                                           \n\
}                                               \n\
";

PRIVATE int cmd_connect(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *jwt = gobj_read_str_attr(gobj, "jwt");
    const char *url = gobj_read_str_attr(gobj, "url");
    const char *yuno_name = gobj_read_str_attr(gobj, "yuno_name");
    const char *yuno_role = gobj_read_str_attr(gobj, "yuno_role");
    const char *yuno_service = gobj_read_str_attr(gobj, "yuno_service");

    /*
     *  Each display window has a gobj to send the commands (saved in user_data).
     *  For external agents create a filter-chain of gobjs
     */
    json_t * jn_config_variables = json_pack("{s:{s:s, s:s, s:s, s:s, s:s}}",
        "__json_config_variables__",
            "__jwt__", jwt,
            "__url__", url,
            "__yuno_name__", yuno_name,
            "__yuno_role__", yuno_role,
            "__yuno_service__", yuno_service
    );
    char *sjson_config_variables = json2str(jn_config_variables);
    JSON_DECREF(jn_config_variables);

    /*
     *  Get schema to select tls or not
     */
    char schema[20]={0}, host[120]={0}, port[40]={0};
    parse_http_url(url, schema, sizeof(schema), host, sizeof(host), port, sizeof(port), FALSE);

    char *agent_config = agent_insecure_config;
    if(strcmp(schema, "wss")==0) {
        agent_config = agent_secure_config;
    }

    hgobj gobj_remote_agent = gobj_create_tree(
        gobj,
        agent_config,
        sjson_config_variables,
        "EV_ON_SETUP",
        "EV_ON_SETUP_COMPLETE"
    );
    gbmem_free(sjson_config_variables);

    gobj_start_tree(gobj_remote_agent);

    if(priv->verbose)  {
        printf("Connecting to %s...\n", url);
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE GBUFFER *source2base64(const char *source, char *comment, int commentlen)
{
    /*------------------------------------------------*
     *          Check source
     *  Frequently, You want install install the output
     *  of your yuno's make install command.
     *------------------------------------------------*/
    if(empty_string(source)) {
        snprintf(comment, commentlen, "%s", "source empty");
        return 0;
    }

    char path[NAME_MAX];
    if(access(source, 0)==0 && is_regular_file(source)) {
        snprintf(path, sizeof(path), "%s", source);
    } else {
        snprintf(path, sizeof(path), "/yuneta/development/output/yunos/%s", source);
    }

    if(access(path, 0)!=0) {
        snprintf(comment, commentlen, "source '%s' not found", source);
        return 0;
    }
    if(!is_regular_file(path)) {
        snprintf(comment, commentlen, "source '%s' is not a regular file", path);
        return 0;
    }
    GBUFFER *gbuf_b64 = gbuf_file2base64(path);
    if(!gbuf_b64) {
        snprintf(comment, commentlen, "conversion '%s' to base64 failed", path);
    }
    return gbuf_b64;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE GBUFFER * replace_cli_vars(hgobj gobj, const char *command, char *comment, int commentlen)
{
    GBUFFER *gbuf = gbuf_create(4*1024, gbmem_get_maximum_block(), 0, 0);
    char *command_ = gbmem_strdup(command);
    char *p = command_;
    char *n, *f;
    while((n=strstr(p, "$$"))) {
        *n = 0;
        gbuf_append(gbuf, p, strlen(p));

        n += 2;
        if(*n == '(') {
            f = strchr(n, ')');
        } else {
            gbuf_decref(gbuf);
            gbmem_free(command_);
            snprintf(comment, commentlen, "%s", "Bad format of $$: use $$(..)");
            return 0;
        }
        if(!f) {
            gbuf_decref(gbuf);
            gbmem_free(command_);
            snprintf(comment, commentlen, "%s", "Bad format of $$: use $$(...)");
            return 0;
        }
        *n = 0;
        n++;
        *f = 0;
        f++;

        GBUFFER *gbuf_b64 = source2base64(n, comment, commentlen);
        if(!gbuf_b64) {
            gbuf_decref(gbuf);
            gbmem_free(command_);
            return 0;
        }

        gbuf_append(gbuf, "'", 1);
        gbuf_append_gbuf(gbuf, gbuf_b64);
        gbuf_append(gbuf, "'", 1);
        gbuf_decref(gbuf_b64);

        p = f;
    }
    if(!empty_string(p)) {
        gbuf_append(gbuf, p, strlen(p));
    }

    gbmem_free(command_);
    return gbuf;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int execute_command(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *command = sdata_read_str(priv->hs, "command");
    if(!command) {
        printf("\nError: no command\n");
        return 0;
    }
    char comment[512]={0};
    if(priv->verbose) {
        printf("\n--> '%s'\n", command);
    }

    GBUFFER *gbuf_parsed_command = replace_cli_vars(gobj, command, comment, sizeof(comment));
    if(!gbuf_parsed_command) {
        printf("Error %s.\n", empty_string(comment)?"replace_cli_vars() FAILED":comment),
        gobj_set_exit_code(-1);
        gobj_shutdown();
        return 0;
    }
    char *xcmd = gbuf_cur_rd_pointer(gbuf_parsed_command);

    json_t *kw_clone = 0;
    json_t *kw = sdata_read_json(priv->hs, "kw");
    if(kw) {
        kw_clone = msg_iev_pure_clone(kw);
    }
    gobj_command(priv->remote_service, xcmd, kw_clone, gobj);
    gbuf_decref(gbuf_parsed_command);

    set_timeout(priv->timer, priv->timeout);
    gobj_change_state(gobj, "ST_WAIT_RESPONSE");
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int tira_dela_cola(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  A por el próximo command
     */
    priv->i_hs = rc_next_instance(priv->i_hs, (rc_resource_t **)&priv->hs);
    if(priv->i_hs) {
        /*
         *  Hay mas comandos
         */
        return execute_command(gobj);
    }

    /*
     *  No hay mas comandos.
     *  Se ha terminado el ciclo
     *  Mira si se repite
     */
    if(priv->repeat > 0) {
        priv->repeat--;
    }

    if(priv->repeat == -1 || priv->repeat > 0) {
        priv->i_hs = rc_first_instance(&priv->tests_iter, (rc_resource_t **)&priv->hs);
        execute_command(gobj);
    } else {
        if(priv->verbose) {
            printf("\n==> All done!\n");
        } else {
            printf("\n");
        }
        gobj_shutdown();
    }

    return 0;
}



            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *  Execute tests of input parameters when the route is opened.
 ***************************************************************************/
PRIVATE int ac_on_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *agent_name = kw_get_str(kw, "remote_yuno_name", 0, 0); // remote agent name

    printf("Connected to '%s'.\n", agent_name);

    priv->remote_service = src;

    /*
     *  Empieza la tralla
     */
    priv->i_hs = rc_first_instance(&priv->tests_iter, (rc_resource_t **)&priv->hs);
    if(priv->i_hs) {
        execute_command(gobj);
    } else {
        printf("No commands to execute.\n"),
        gobj_set_exit_code(-1);
        gobj_shutdown();
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);

    if(!gobj_is_running(gobj)) {
        KW_DECREF(kw);
        return 0;
    }
    printf("Disconnected.\n"),

    gobj_set_exit_code(-1);
    gobj_shutdown();

    // No puedo parar y destruir con libuv.
    // De momento conexiones indestructibles, destruibles solo con la salida del yuno.
    // Hasta que quite la dependencia de libuv. FUTURE
    //gobj_stop_tree(src);
    //gobj_destroy(tree);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *  Response from agent mt_stats
 *  Response from agent mt_command
 *  Response to asychronous queries
 *  The received event is generated by a Counter with kw:
 *      max_count: items raised
 *      cur_count: items reached with success
 ***************************************************************************/
PRIVATE int ac_mt_command_answer(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    //const char *command = sdata_read_str(priv->hs, "command");
    json_t *jn_response = sdata_read_json(priv->hs, "response");
    json_t *jn_filter = sdata_read_json(priv->hs, "filter");
    BOOL ignore_fail = sdata_read_bool(priv->hs, "ignore_fail");
    BOOL without_metadata = sdata_read_bool(priv->hs, "without_metadata");
    BOOL without_private = sdata_read_bool(priv->hs, "without_private");

    if(jn_filter) {
        json_t *new_kw = kw_clone_by_keys(json_incref(kw), json_incref(jn_filter), TRUE);
        KW_DECREF(kw);
        kw = new_kw;
    }

    if(jn_response) {
        BOOL match = kwid_compare_records(
            kw,             // record
            jn_response,    // expected
            without_metadata,
            without_private,
            (priv->verbose > 1)?1:0
        );
        if(!match) {
            gobj_set_exit_code(-1);
            if(priv->verbose) {
                printf("%s  --> ERROR: %s %s\n", On_Red BWhite, "response not match", Color_Off);
                if(priv->verbose > 1) {
                    print_json2("received", kw);
                    print_json2("expected", jn_response);
                }
            } else {
                printf("%sX%s", On_Red BWhite,Color_Off);
            }
            if(!ignore_fail) {
                KW_DECREF(kw);
                printf("\n");
                gobj_shutdown();
                return -1;
            }

        } else {
            if(priv->verbose) {
                printf("  --> OK\n");
                if(priv->verbose > 1) {
                    print_json2("received", kw);
                }
            } else {
                printf(".");
            }
        }
    } else {
        int result = kw_get_int(kw, "result", -1, 0);
        const char *comment = kw_get_str(kw, "comment", "", 0);

        if(result<0) {
            gobj_set_exit_code(-1);
            if(priv->verbose) {
                printf("%s  --> ERROR: %s %s\n", On_Red BWhite, comment, Color_Off);
                if(priv->verbose > 1) {
                    print_json2("received", kw);
                }
            } else {
                printf("%sX%s", On_Red BWhite,Color_Off);
            }
            if(!ignore_fail) {
                KW_DECREF(kw);
                printf("\n");
                gobj_shutdown();
                return -1;
            }
        } else {
            if(priv->verbose) {
                printf("  --> OK\n");
                if(priv->verbose > 1) {
                    print_json2("received", kw);
                }
            } else {
                printf(".");
            }
        }
    }

    clear_timeout(priv->timer);
    tira_dela_cola(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    printf("Timeout \n"),
    gobj_set_exit_code(-1);
    gobj_shutdown();

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    {"EV_ON_OPEN",                  0, 0, 0},
    {"EV_ON_CLOSE",                 0, 0, 0},
    {"EV_MT_STATS_ANSWER",          EVF_PUBLIC_EVENT, 0, 0},
    {"EV_MT_COMMAND_ANSWER",        EVF_PUBLIC_EVENT, 0, 0},
    // bottom input
    {"EV_STOPPED",                  0, 0, 0},
    {"EV_TIMEOUT",                  0, 0, 0},
    // internal
    {NULL, 0, 0, 0}
};
PRIVATE const EVENT output_events[] = {
    {NULL, 0, 0, 0}
};
PRIVATE const char *state_names[] = {
    "ST_DISCONNECTED",
    "ST_CONNECTED",
    "ST_WAIT_RESPONSE",
    NULL
};

PRIVATE EV_ACTION ST_DISCONNECTED[] = {
    {"EV_ON_OPEN",                  ac_on_open,                 "ST_CONNECTED"},
    {"EV_ON_CLOSE",                 ac_on_close,                0},
    {"EV_STOPPED",                  0,                          0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_CONNECTED[] = {
    {"EV_ON_CLOSE",                 ac_on_close,                "ST_DISCONNECTED"},
    {"EV_STOPPED",                  0,                          0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_WAIT_RESPONSE[] = {
    {"EV_ON_CLOSE",                 ac_on_close,                "ST_DISCONNECTED"},
    {"EV_MT_STATS_ANSWER",          ac_mt_command_answer,       0},
    {"EV_MT_COMMAND_ANSWER",        ac_mt_command_answer,       0},
    {"EV_TIMEOUT",                  ac_timeout,                 0},
    {"EV_STOPPED",                  0,                          0},
    {0,0,0}
};


PRIVATE EV_ACTION *states[] = {
    ST_DISCONNECTED,
    ST_CONNECTED,
    ST_WAIT_RESPONSE,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_YTESTS_NAME,
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //mt_play,
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command_parser,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_authorization_parser,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_topic_jtree,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_node_tree,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    0,  // acl
    s_user_trace_level,
    0,  // command_table,
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_ytests(void)
{
    return &_gclass;
}
