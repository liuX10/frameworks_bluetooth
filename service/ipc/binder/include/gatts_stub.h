/****************************************************************************
 *  Copyright (C) 2023 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ***************************************************************************/

#ifndef __BT_GATTS_STUB_H__
#define __BT_GATTS_STUB_H__

#include <stdbool.h>
#include <stdint.h>
#include <uchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <android/binder_manager.h>

typedef struct {
    AIBinder_Class* clazz;
    AIBinder_Weak* WeakBinder;
    void* usr_data;
} IBtGattServer;

typedef struct {
    AIBinder_Class* clazz;
    AIBinder* binder;
} BpBtGattServer;

typedef enum {
    IGATT_SERVER_REGISTER_SERVICE = FIRST_CALL_TRANSACTION,
    IGATT_SERVER_UNREGISTER_SERVICE,
    IGATT_SERVER_CONNECT,
    IGATT_SERVER_DISCONNECT,
    IGATT_SERVER_CREATE_SERVICE_TABLE,
    IGATT_SERVER_START,
    IGATT_SERVER_STOP,
    IGATT_SERVER_RESPONSE,
    IGATT_SERVER_NOTIFY,
    IGATT_SERVER_INDICATE,
} IBtGattServer_Call;

#define GATT_SERVER_BINDER_INSTANCE "Vela.Bluetooth.Gatt.Server"

binder_status_t BtGattServer_addService(IBtGattServer* iGatts, const char* instance);
AIBinder* BtGattServer_getService(BpBtGattServer** bpGatts, const char* instance);

#ifdef __cplusplus
}
#endif
#endif /* __BT_GATTS_STUB_H__ */