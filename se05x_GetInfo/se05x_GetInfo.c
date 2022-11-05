/* Copyright 2019,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <string.h>
#include <nxEnsure.h>
#include <sm_const.h>

#include "ex_sss_auth.h"
#include "global_platf.h"
#include "smCom.h"

#ifndef SIMW_DEMO_ENABLE__DEMO_SE05X_GETINFO
#include "UWBIOT_APP_BUILD.h"
#endif

#if defined(SIMW_DEMO_ENABLE__DEMO_SE05X_GETINFO)

static ex_sss_boot_ctx_t gex_sss_get_info_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_get_info_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

#include <ex_sss_main_inc.h>

static sss_status_t Iot_Applet_Identify(sss_se05x_session_t *pSession, int getUid);
static sss_status_t iot_applet_session_open(ex_sss_boot_ctx_t *pCtx);

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    /* Try connecting to iot applet */
    status = iot_applet_session_open(pCtx);
    if (status != kStatus_SSS_Success) {
        LOG_I("No IoT applet found");
    }
    else {
        /* Get UID, applet version and config details */
        status = Iot_Applet_Identify(pSession, 1);
        if (status != kStatus_SSS_Success) {
            LOG_I("Error in Iot_Applet_Identify");
        }
    }

    status = kStatus_SSS_Success;
cleanup:
    return status;
}

static sss_status_t iot_applet_session_open(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    const char *portName;

    ex_sss_session_close(pCtx);

    status = ex_sss_boot_connectstring(gex_sss_argc, gex_sss_argv, &portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_boot_connectstring Failed");
        goto cleanup;
    }

    pCtx->se05x_open_ctx.skip_select_applet = 0;

    status = ex_sss_boot_open(pCtx, portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed");
        goto cleanup;
    }

    status = kStatus_SSS_Success;
cleanup:
    return status;
}

#define CHECK_FEATURE_PRESENT(AppletConfig, ITEM)                                            \
    if (((kSE05x_AppletConfig_##ITEM) == ((AppletConfig) & (kSE05x_AppletConfig_##ITEM)))) { \
        LOG_I("With    " #ITEM);                                                             \
    }                                                                                        \
    else {                                                                                   \
        LOG_I("WithOut " #ITEM);                                                             \
    }

static sss_status_t Iot_Applet_Identify(sss_se05x_session_t *pSession, int getUid)
{
    sss_status_t status = kStatus_SSS_Fail;
    smStatus_t sw_status;
    SE05x_Result_t result = kSE05x_Result_NA;
    uint8_t uid[SE050_MODULE_UNIQUE_ID_LEN];
    size_t uidLen = sizeof(uid);
    uint8_t applet_version[7];
    size_t applet_versionLen = sizeof(applet_version);

    if (getUid == 1) {
        sw_status = Se05x_API_CheckObjectExists(&pSession->s_ctx, kSE05x_AppletResID_UNIQUE_ID, &result);
        if (SM_OK != sw_status) {
            LOG_E("Failed Se05x_API_CheckObjectExists");
        }
        else {
            sw_status =
                Se05x_API_ReadObject(&pSession->s_ctx, kSE05x_AppletResID_UNIQUE_ID, 0, (uint16_t)uidLen, uid, &uidLen);
            if (SM_OK != sw_status) {
                LOG_E("Failed Se05x_API_CheckObjectExists");
                goto cleanup;
            }
            LOG_W("#####################################################");
            LOG_AU8_I(uid, uidLen);
        }
    }

    // VersionInfo is a 7 - byte value consisting of :
    // - 1 - byte Major applet version
    // - 1 - byte Minor applet version
    // - 1 - byte patch applet version
    // - 2 - byte AppletConfig, indicating the supported applet features
    // - 2-byte Secure Box version: major version (MSB) concatenated with minor version (LSB).

    sw_status = Se05x_API_GetVersion(&pSession->s_ctx, applet_version, &applet_versionLen);
    if (SM_OK != sw_status) {
        LOG_E("Failed Se05x_API_GetVersion");
        {
            /* In case of FIPS, if the example is not built for PlatSCP, try getting version by applet select again */
            unsigned char appletName[] = APPLET_NAME;
            U8 selectResponseData[32]  = {0};
            U16 selectResponseDataLen  = sizeof(selectResponseData);
            sw_status                  = (smStatus_t)GP_Select(pSession->s_ctx.conn_ctx,
                (U8 *)&appletName,
                APPLET_NAME_LEN,
                selectResponseData,
                &selectResponseDataLen);
            if (sw_status != SM_OK) {
                LOG_E("Could not select applet.");
                goto cleanup;
            }
            if (selectResponseDataLen != applet_versionLen) {
                goto cleanup;
            }
            if (selectResponseDataLen > sizeof(applet_version)) {
                goto cleanup;
            }           
            memcpy(applet_version, selectResponseData, selectResponseDataLen);
        }
    }
    LOG_W("#####################################################");
    LOG_I("Applet Major = %d", applet_version[0]);
    LOG_I("Applet Minor = %d", applet_version[1]);
    LOG_I("Applet patch = %d", applet_version[2]);
    LOG_I("AppletConfig = %02X%02X", applet_version[3], applet_version[4]);
    {
        U16 AppletConfig = applet_version[3] << 8 | applet_version[4];
        CHECK_FEATURE_PRESENT(AppletConfig, ECDSA_ECDH_ECDHE);
        CHECK_FEATURE_PRESENT(AppletConfig, EDDSA);
        CHECK_FEATURE_PRESENT(AppletConfig, DH_MONT);
        CHECK_FEATURE_PRESENT(AppletConfig, HMAC);
        CHECK_FEATURE_PRESENT(AppletConfig, RSA_PLAIN);
        CHECK_FEATURE_PRESENT(AppletConfig, RSA_CRT);
        CHECK_FEATURE_PRESENT(AppletConfig, AES);
        CHECK_FEATURE_PRESENT(AppletConfig, DES);
        CHECK_FEATURE_PRESENT(AppletConfig, PBKDF);
        CHECK_FEATURE_PRESENT(AppletConfig, TLS);
        CHECK_FEATURE_PRESENT(AppletConfig, MIFARE);
        CHECK_FEATURE_PRESENT(AppletConfig, I2CM);
    }
    LOG_I("Internal = %02X%02X", applet_version[5], applet_version[6]);

    status = kStatus_SSS_Success;
cleanup:
    return status;
}

#endif // SIMW_DEMO_ENABLE__DEMO_SE05X_GETINFO
