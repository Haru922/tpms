#ifndef __TPMS_H__
#define __TPMS_H__

#include <stdio.h>
#include <stdlib.h>

#define TPMS_VERSION       "0.0.1"
#define LSF_PASSPHRASE_DIR "/var/tmp/lsf/.passphrase"

typedef enum {
  TPMS_OPT_INSERT,
  TPMS_OPT_DELETE,
  TPMS_OPT_UPDATE
} TPMS_OPT;

typedef enum {
  TPMS_FIELD_PUBLIC_KEY,
  TPMS_FIELD_SETTINGS, 
  TPMS_FIELD_HASH_CHECK,
  TPMS_FIELD_START_CMD,
  TPMS_FIELD_STOP_CMD,
  TPMS_FIELD_APP_USING,
  TPMS_FIELD_EXE_TYPE,
  TPMS_FIELD_PRIVATE_KEY,
  TPMS_FIELD_PERMISSION,
  TPMS_FIELD_DISPLAY_NAME,
  TPMS_FIELD_ABS_PATH,
  TPMS_FIELD_AUTO_UPDATE,
  TPMS_FIELD_EXP,
  TPMS_FIELD_DBUS_NAME,
  TPMS_FIELD_NUMS
} TPMS_FIELD;

const char *tpms_key[] = { "public_key", "settings",
                           "hash_check", "start_cmd",
                           "stop_cmd", "app_using",
                           "exe_type", "private_key",
                           "permission", "display_name",
                           "abs_path", "auto_update",
                           "exp", "dbus_name" };

const char *lsf_modules[] = { "kr.gooroom.ghub", "kr.gooroom.gauth", "kr.gooroom.gcontroller",
                              "kr.gooroom.agent", "kr.gooroom.controlcenter", "kr.gooroom.lsfccpanel",
                              "kr.gooroom.gfim", NULL };

char *tpms_value[TPMS_FIELD_NUMS] = { NULL, NULL,
                                      "false", NULL,
                                      "", "true",
                                      "non systemd service", NULL,
                                      "root", NULL,
                                      NULL, "false",
                                      "12", NULL };

#endif
