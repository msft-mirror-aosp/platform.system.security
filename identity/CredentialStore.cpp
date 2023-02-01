/*
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "credstore"

#include <algorithm>
#include <optional>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/hardware/security/keymint/IRemotelyProvisionedComponent.h>
#include <android/hardware/security/keymint/RpcHardwareInfo.h>
#include <android/security/remoteprovisioning/IRemotelyProvisionedKeyPool.h>
#include <android/security/remoteprovisioning/RemotelyProvisionedKey.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <vintf/VintfObject.h>

#include "Credential.h"
#include "CredentialData.h"
#include "CredentialStore.h"
#include "RemotelyProvisionedKey.h"
#include "Session.h"
#include "Util.h"
#include "WritableCredential.h"

namespace android {
namespace security {
namespace identity {
namespace {

using ::android::security::remoteprovisioning::IRemotelyProvisionedKeyPool;
using ::android::security::rkp::IRemoteProvisioning;

bool useRkpd() {
    return android::base::GetBoolProperty("remote_provisioning.enable_rkpd",
                                          /*default_value=*/false);
}

}  // namespace

CredentialStore::CredentialStore(const std::string& dataPath, sp<IIdentityCredentialStore> hal)
    : dataPath_(dataPath), hal_(hal) {}

bool CredentialStore::init() {
    Status status = hal_->getHardwareInformation(&hwInfo_);
    if (!status.isOk()) {
        LOG(ERROR) << "Error getting hardware information: " << status.toString8();
        return false;
    }
    halApiVersion_ = hal_->getInterfaceVersion();

    if (hwInfo_.isRemoteKeyProvisioningSupported) {
        status = hal_->getRemotelyProvisionedComponent(&rpc_);
        if (!status.isOk()) {
            LOG(ERROR) << "Error getting remotely provisioned component: " << status;
            return false;
        }
    }

    LOG(INFO) << "Connected to Identity Credential HAL with API version " << halApiVersion_
              << " and name '" << hwInfo_.credentialStoreName << "' authored by '"
              << hwInfo_.credentialStoreAuthorName << "' with chunk size " << hwInfo_.dataChunkSize
              << " directoAccess set to " << (hwInfo_.isDirectAccess ? "true" : "false")
              << " and remote key provisioning support "
              << (hwInfo_.isRemoteKeyProvisioningSupported ? "enabled" : "disabled");
    return true;
}

CredentialStore::~CredentialStore() {}

Status CredentialStore::getSecurityHardwareInfo(SecurityHardwareInfoParcel* _aidl_return) {
    SecurityHardwareInfoParcel info;
    info.directAccess = hwInfo_.isDirectAccess;
    info.supportedDocTypes = hwInfo_.supportedDocTypes;
    *_aidl_return = info;
    return Status::ok();
};

Status CredentialStore::createCredential(const std::string& credentialName,
                                         const std::string& docType,
                                         sp<IWritableCredential>* _aidl_return) {
    uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
    optional<bool> credentialExists =
        CredentialData::credentialExists(dataPath_, callingUid, credentialName);
    if (!credentialExists.has_value()) {
        return Status::fromServiceSpecificError(
            ERROR_GENERIC, "Error determining if credential with given name exists");
    }
    if (credentialExists.value()) {
        return Status::fromServiceSpecificError(ERROR_ALREADY_PERSONALIZED,
                                                "Credential with given name already exists");
    }

    if (hwInfo_.supportedDocTypes.size() > 0) {
        if (std::find(hwInfo_.supportedDocTypes.begin(), hwInfo_.supportedDocTypes.end(),
                      docType) == hwInfo_.supportedDocTypes.end()) {
            return Status::fromServiceSpecificError(ERROR_DOCUMENT_TYPE_NOT_SUPPORTED,
                                                    "No support for given document type");
        }
    }

    sp<IWritableIdentityCredential> halWritableCredential;
    Status status = hal_->createCredential(docType, false, &halWritableCredential);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }

    if (hwInfo_.isRemoteKeyProvisioningSupported) {
        status = setRemotelyProvisionedAttestationKey(halWritableCredential.get());
        if (!status.isOk()) {
            LOG(WARNING) << status.toString8()
                         << "\nUnable to fetch remotely provisioned attestation key, falling back "
                         << "to the factory-provisioned attestation key.";
        }
    }

    sp<IWritableCredential> writableCredential = new WritableCredential(
        dataPath_, credentialName, docType, false, hwInfo_, halWritableCredential);
    *_aidl_return = writableCredential;
    return Status::ok();
}

Status CredentialStore::getCredentialCommon(const std::string& credentialName, int32_t cipherSuite,
                                            sp<IPresentationSession> halSessionBinder,
                                            sp<ICredential>* _aidl_return) {
    *_aidl_return = nullptr;

    uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
    optional<bool> credentialExists =
        CredentialData::credentialExists(dataPath_, callingUid, credentialName);
    if (!credentialExists.has_value()) {
        return Status::fromServiceSpecificError(
            ERROR_GENERIC, "Error determining if credential with given name exists");
    }
    if (!credentialExists.value()) {
        return Status::fromServiceSpecificError(ERROR_NO_SUCH_CREDENTIAL,
                                                "Credential with given name doesn't exist");
    }

    // Note: IdentityCredentialStore.java's CipherSuite enumeration and CipherSuite from the
    // HAL is manually kept in sync. So this cast is safe.
    sp<Credential> credential =
        new Credential(CipherSuite(cipherSuite), dataPath_, credentialName, callingUid, hwInfo_,
                       hal_, halSessionBinder, halApiVersion_);

    Status loadStatus = credential->ensureOrReplaceHalBinder();
    if (!loadStatus.isOk()) {
        LOG(ERROR) << "Error loading credential";
    } else {
        *_aidl_return = credential;
    }
    return loadStatus;
}

Status CredentialStore::getCredentialByName(const std::string& credentialName, int32_t cipherSuite,
                                            sp<ICredential>* _aidl_return) {
    return getCredentialCommon(credentialName, cipherSuite, nullptr, _aidl_return);
}

Status CredentialStore::createPresentationSession(int32_t cipherSuite, sp<ISession>* _aidl_return) {
    sp<IPresentationSession> halPresentationSession;
    Status status =
        hal_->createPresentationSession(CipherSuite(cipherSuite), &halPresentationSession);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }

    *_aidl_return = new Session(cipherSuite, halPresentationSession, this);
    return Status::ok();
}

Status CredentialStore::setRemotelyProvisionedAttestationKey(
    IWritableIdentityCredential* halWritableCredential) {
    std::vector<uint8_t> keyBlob;
    std::vector<uint8_t> encodedCertChain;
    Status status;

    if (useRkpd()) {
        LOG(INFO) << "Fetching attestation key from RKPD";

        uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
        auto rpcKeyFuture = getRpcKeyFuture(rpc_, callingUid);
        if (!rpcKeyFuture) {
            return Status::fromServiceSpecificError(ERROR_GENERIC, "Error in getRpcKeyFuture()");
        }

        if (rpcKeyFuture->wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
            return Status::fromServiceSpecificError(
                ERROR_GENERIC, "Waiting for remotely provisioned attestation key timed out");
        }

        std::optional<::android::security::rkp::RemotelyProvisionedKey> key = rpcKeyFuture->get();
        if (!key) {
            return Status::fromServiceSpecificError(
                ERROR_GENERIC, "Failed to get remotely provisioned attestation key");
        }

        if (key->keyBlob.empty()) {
            return Status::fromServiceSpecificError(
                ERROR_GENERIC, "Remotely provisioned attestation key blob is empty");
        }

        keyBlob = std::move(key->keyBlob);
        encodedCertChain = std::move(key->encodedCertChain);
    } else {
        LOG(INFO) << "Fetching attestation key from remotely provisioned key pool.";

        sp<IRemotelyProvisionedKeyPool> keyPool =
            android::waitForService<IRemotelyProvisionedKeyPool>(
                IRemotelyProvisionedKeyPool::descriptor);
        if (!keyPool) {
            return Status::fromServiceSpecificError(
                ERROR_GENERIC, "Error getting IRemotelyProvisionedKeyPool HAL");
        }

        std::optional<std::string> rpcId = getRpcId(rpc_);
        if (!rpcId) {
            return Status::fromServiceSpecificError(
                ERROR_GENERIC, "Error getting remotely provisioned component id");
        }

        uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
        ::android::security::remoteprovisioning::RemotelyProvisionedKey key;
        Status status = keyPool->getAttestationKey(callingUid, *rpcId, &key);
        if (!status.isOk()) {
            return status;
        }

        keyBlob = std::move(key.keyBlob);
        encodedCertChain = std::move(key.encodedCertChain);
    }

    status = halWritableCredential->setRemotelyProvisionedAttestationKey(keyBlob, encodedCertChain);
    if (!status.isOk()) {
        LOG(ERROR) << "Error setting remotely provisioned attestation key on credential";
        return status;
    }
    return Status::ok();
}

}  // namespace identity
}  // namespace security
}  // namespace android
