//#include "../config.h"
#include "log_file.h"
//#include "log_sguil.h"

//extern globalconfig config;

void init_logging()
{
    //if (you want to log to file)
        bstring file = bfromcstr("/tmp/prads-asset.log");
        init_output_log_file(file);
        bdestroy(file);
    //

    //if (you want to log to sguil - FIFO)
//        bstring sguil = bfromcstr("/tmp/prads-asset.fifo");
//        init_output_sguil(sguil);
//        bdestroy(sguil);
    //
}


void end_logging()
{
    end_output_log_file ();
}

char *hex2mac(const char *mac)
{

    static char buf[32];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             (mac[0] & 0xFF), (mac[1] & 0xFF), (mac[2] & 0xFF),
             (mac[3] & 0xFF), (mac[4] & 0xFF), (mac[5] & 0xFF));

    return buf;
}

