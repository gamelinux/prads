//#include "../config.h"
#include "log_file.h"
//#include "log_sguil.h"

//extern globalconfig config;

void init_logging()
{
    //if (you want to log to file)
        init_output_log_file(bfromcstr("/tmp/prads-asset.log"));
}

char *hex2mac(const char *mac)
{

    static char buf[32];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             (mac[0] & 0xFF), (mac[1] & 0xFF), (mac[2] & 0xFF),
             (mac[3] & 0xFF), (mac[4] & 0xFF), (mac[5] & 0xFF));

    return buf;
}

