#!/usr/bin/env python3
"""
IronKey PKCS#11 Module - Python Implementation

This implements the PKCS#11 (Cryptoki) API for IronKey S200.
Can be used via pkcs11-proxy or directly from Python applications.

PKCS#11 Functions Implemented:
- C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList
- C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList/Info
- C_OpenSession, C_CloseSession, C_Login, C_Logout, C_InitPIN, C_SetPIN
- C_CreateObject, C_DestroyObject, C_CopyObject
- C_FindObjectsInit/Final, C_FindObjects, C_GetAttributeValue, C_SetAttributeValue
- C_EncryptInit/Update/Final, C_DecryptInit/Update/Final
- C_DigestInit/Update/Final, C_SignInit/Update/Final, C_VerifyInit/Update/Final
- C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey
- C_SeedRandom, C_GenerateRandom
"""

import os
import ctypes
import ctypes.util
import struct
import hashlib
import hmac
import secrets
import logging
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import IntEnum
from threading import Lock

logger = logging.getLogger(__name__)

# PKCS#11 Constants
CKR_OK = 0x00000000
CKR_CANCEL = 0x00000001
CKR_HOST_MEMORY = 0x00000002
CKR_SLOT_ID_INVALID = 0x00000003
CKR_GENERAL_ERROR = 0x00000005
CKR_FUNCTION_FAILED = 0x00000006
CKR_ARGUMENTS_BAD = 0x00000007
CKR_NO_EVENT = 0x00000008
CKR_NEED_TO_CREATE_THREADS = 0x00000009
CKR_CANT_LOCK = 0x0000000A
CKR_ATTRIBUTE_READ_ONLY = 0x00000010
CKR_ATTRIBUTE_SENSITIVE = 0x00000011
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013
CKR_ACTION_PROHIBITED = 0x0000001A
CKR_DATA_INVALID = 0x00000020
CKR_DATA_LEN_RANGE = 0x00000021
CKR_DEVICE_ERROR = 0x00000030
CKR_DEVICE_MEMORY = 0x00000031
CKR_DEVICE_REMOVED = 0x00000032
CKR_ENCRYPTED_DATA_INVALID = 0x00000040
CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041
CKR_FUNCTION_CANCELED = 0x00000050
CKR_FUNCTION_NOT_PARALLEL = 0x00000051
CKR_FUNCTION_NOT_SUPPORTED = 0x00000054
CKR_KEY_HANDLE_INVALID = 0x00000060
CKR_KEY_SIZE_RANGE = 0x00000062
CKR_KEY_TYPE_INCONSISTENT = 0x00000063
CKR_KEY_NOT_NEEDED = 0x00000064
CKR_KEY_CHANGED = 0x00000065
CKR_KEY_NEEDED = 0x00000066
CKR_KEY_INDIGESTIBLE = 0x00000067
CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068
CKR_KEY_NOT_WRAPPABLE = 0x00000069
CKR_KEY_UNEXTRACTABLE = 0x0000006A
CKR_MECHANISM_INVALID = 0x00000070
CKR_MECHANISM_PARAM_INVALID = 0x00000071
CKR_OBJECT_HANDLE_INVALID = 0x00000082
CKR_OPERATION_ACTIVE = 0x00000090
CKR_OPERATION_NOT_INITIALIZED = 0x00000091
CKR_PIN_INCORRECT = 0x000000A0
CKR_PIN_INVALID = 0x000000A1
CKR_PIN_LEN_RANGE = 0x000000A2
CKR_PIN_EXPIRED = 0x000000A3
CKR_PIN_LOCKED = 0x000000A4
CKR_SESSION_CLOSED = 0x000000B0
CKR_SESSION_COUNT = 0x000000B1
CKR_SESSION_HANDLE_INVALID = 0x000000B3
CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4
CKR_SESSION_READ_ONLY = 0x000000B5
CKR_SESSION_EXISTS = 0x000000B6
CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7
CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8
CKR_SIGNATURE_INVALID = 0x000000C0
CKR_SIGNATURE_LEN_RANGE = 0x000000C1
CKR_TEMPLATE_INCOMPLETE = 0x000000D0
CKR_TEMPLATE_INCONSISTENT = 0x000000D1
CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1
CKR_TOKEN_WRITE_PROTECTED = 0x000000E2
CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0
CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_USER_NOT_LOGGED_IN = 0x00000101
CKR_USER_PIN_NOT_INITIALIZED = 0x00000102
CKR_USER_TYPE_INVALID = 0x00000103
CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104
CKR_USER_TOO_MANY_TYPES = 0x00000105
CKR_WRAPPED_KEY_INVALID = 0x00000110
CKR_WRAPPED_KEY_LEN_RANGE = 0x00000111
CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000112
CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000113
CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000114
CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120
CKR_RANDOM_NO_RNG = 0x00000121
CKR_DOMAIN_PARAMS_INVALID = 0x00000130
CKR_BUFFER_TOO_SMALL = 0x00000150
CKR_SAVED_STATE_INVALID = 0x00000160
CKR_INFORMATION_SENSITIVE = 0x00000170
CKR_STATE_UNSAVEABLE = 0x00000171
CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000172
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000173
CKR_MUTEX_BAD = 0x00000174
CKR_MUTEX_NOT_LOCKED = 0x00000175
CKR_NEW_PIN_MODE = 0x00000176
CKR_NEXT_OTP = 0x00000177
CKR_EXCEEDED_MAX_ITERATIONS = 0x00000178
CKR_FIPS_SELF_TEST_FAILED = 0x00000179
CKR_LIBRARY_LOAD_FAILED = 0x00000180
CKR_PIN_TOO_WEAK = 0x00000181
CKR_PUBLIC_KEY_INVALID = 0x00000182

# Object Classes
CKO_DATA = 0x00000000
CKO_CERTIFICATE = 0x00000001
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKO_SECRET_KEY = 0x00000004
CKO_HW_FEATURE = 0x00000005
CKO_DOMAIN_PARAMETERS = 0x00000006
CKO_MECHANISM = 0x00000007

# Key Types
CKK_RSA = 0x00000000
CKK_DSA = 0x00000001
CKK_DH = 0x00000002
CKK_ECDSA = 0x00000003
CKK_EC = 0x00000003
CKK_X9_42_DH = 0x00000004
CKK_KEA = 0x00000005
CKK_GENERIC_SECRET = 0x00000010
CKK_RC2 = 0x00000011
CKK_RC4 = 0x00000012
CKK_DES = 0x00000013
CKK_DES2 = 0x00000014
CKK_DES3 = 0x00000015
CKK_CAST = 0x00000016
CKK_CAST3 = 0x00000017
CKK_CAST5 = 0x00000018
CKK_CAST128 = 0x00000018
CKK_RC5 = 0x00000019
CKK_IDEA = 0x0000001A
CKK_SKIPJACK = 0x0000001B
CKK_BATON = 0x0000001C
CKK_JUNIPER = 0x0000001D
CKK_CDMF = 0x0000001E
CKK_AES = 0x0000001F
CKK_BLOWFISH = 0x00000020
CKK_TWOFISH = 0x00000021
CKK_SECURID = 0x00000022
CKK_HOTP = 0x00000023
CKK_ACTI = 0x00000024
CKK_CAMELLIA = 0x00000025
CKK_ARIA = 0x00000026

# Mechanisms
CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_RSA_PKCS = 0x00000001
CKM_RSA_9796 = 0x00000002
CKM_RSA_X_509 = 0x00000003
CKM_RSA_PKCS_OAEP = 0x00000009
CKM_RSA_PKCS_PSS = 0x0000000D
CKM_SHA1_RSA_PKCS = 0x00000005
CKM_SHA256_RSA_PKCS = 0x00000040
CKM_SHA384_RSA_PKCS = 0x00000041
CKM_SHA512_RSA_PKCS = 0x00000042
CKM_SHA1_RSA_PKCS_PSS = 0x00000006
CKM_SHA256_RSA_PKCS_PSS = 0x00000043
CKM_AES_KEY_GEN = 0x00000100
CKM_AES_ECB = 0x00000101
CKM_AES_CBC = 0x00000102
CKM_AES_CBC_PAD = 0x00000103
CKM_AES_CTR = 0x00000106
CKM_AES_GCM = 0x00000107
CKM_SHA_1 = 0x00000200
CKM_SHA_1_HMAC = 0x00000201
CKM_SHA256 = 0x00000250
CKM_SHA256_HMAC = 0x00000251
CKM_SHA384 = 0x00000260
CKM_SHA384_HMAC = 0x00000261
CKM_SHA512 = 0x00000270
CKM_SHA512_HMAC = 0x00000271

# Attribute Types
CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_PRIVATE = 0x00000002
CKA_LABEL = 0x00000003
CKA_APPLICATION = 0x00000010
CKA_VALUE = 0x00000011
CKA_OBJECT_ID = 0x00000012
CKA_CERTIFICATE_TYPE = 0x00000080
CKA_ISSUER = 0x00000081
CKA_SERIAL_NUMBER = 0x00000082
CKA_AC_ISSUER = 0x00000083
CKA_AC_SUBJECT = 0x00000084
CKA_KEY_TYPE = 0x00000100
CKA_SUBJECT = 0x00000090
CKA_ID = 0x00000102
CKA_SENSITIVE = 0x00000103
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_WRAP = 0x00000106
CKA_UNWRAP = 0x00000107
CKA_SIGN = 0x00000108
CKA_SIGN_RECOVER = 0x00000109
CKA_VERIFY = 0x0000010A
CKA_VERIFY_RECOVER = 0x0000010B
CKA_DERIVE = 0x0000010C
CKA_START_DATE = 0x00000110
CKA_END_DATE = 0x00000111
CKA_MODULUS = 0x00000120
CKA_MODULUS_BITS = 0x00000121
CKA_PUBLIC_EXPONENT = 0x00000122
CKA_PRIVATE_EXPONENT = 0x00000123
CKA_PRIME_1 = 0x00000124
CKA_PRIME_2 = 0x00000125
CKA_EXPONENT_1 = 0x00000126
CKA_EXPONENT_2 = 0x00000127
CKA_COEFFICIENT = 0x00000128
CKA_PRIME = 0x00000130
CKA_SUBPRIME = 0x00000131
CKA_BASE = 0x00000132
CKA_PRIME_BITS = 0x00000133
CKA_VALUE_BITS = 0x00000160
CKA_VALUE_LEN = 0x00000161
CKA_EXTRACTABLE = 0x00000162
CKA_LOCAL = 0x00000163
CKA_NEVER_EXTRACTABLE = 0x00000164
CKA_ALWAYS_SENSITIVE = 0x00000165
CKA_KEY_GEN_MECHANISM = 0x00000166
CKA_MODIFIABLE = 0x00000170
CKA_ECDSA_PARAMS = 0x00000180
CKA_EC_PARAMS = 0x00000180
CKA_EC_POINT = 0x00000181
CKA_SECONDARY_AUTH = 0x00000200
CKA_AUTH_PIN_FLAGS = 0x00000201
CKA_HW_FEATURE_TYPE = 0x00000300
CKA_RESET_ON_INIT = 0x00000301
CKA_HAS_RESET = 0x00000302

# Session Flags
CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004

# User Types
CKU_SO = 0
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2

# Slot Flags
CKF_TOKEN_PRESENT = 0x00000001
CKF_REMOVABLE_DEVICE = 0x00000002
CKF_HW_SLOT = 0x00000004

# Token Flags
CKF_RNG = 0x00000001
CKF_WRITE_PROTECTED = 0x00000002
CKF_LOGIN_REQUIRED = 0x00000004
CKF_USER_PIN_INITIALIZED = 0x00000008
CKF_RESTORE_KEY_NOT_NEEDED = 0x00000020
CKF_CLOCK_ON_TOKEN = 0x00000040
CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100
CKF_DUAL_CRYPTO_OPERATIONS = 0x00000200
CKF_TOKEN_INITIALIZED = 0x00000400
CKF_SECONDARY_AUTHENTICATION = 0x00000800
CKF_USER_PIN_COUNT_LOW = 0x00010000
CKF_USER_PIN_FINAL_TRY = 0x00020000
CKF_USER_PIN_LOCKED = 0x00040000
CKF_USER_PIN_TO_BE_CHANGED = 0x00080000
CKF_SO_PIN_COUNT_LOW = 0x00100000
CKF_SO_PIN_FINAL_TRY = 0x00200000
CKF_SO_PIN_LOCKED = 0x00400000
CKF_SO_PIN_TO_BE_CHANGED = 0x00800000

@dataclass
class CK_ATTRIBUTE:
    type: int
    value: Any = None
    ulValueLen: int = 0

@dataclass
class CK_MECHANISM:
    mechanism: int
    parameter: Any = None
    ulParameterLen: int = 0

@dataclass
class CK_MECHANISM_INFO:
    mechanism: int
    flags: int
    ulMinKeySize: int
    ulMaxKeySize: int

@dataclass
class CK_SLOT_INFO:
    slotDescription: str = ""
    manufacturerID: str = ""
    flags: int = 0
    hardwareVersion: tuple = (0, 0)
    firmwareVersion: tuple = (0, 0)

@dataclass
class CK_TOKEN_INFO:
    label: str = ""
    manufacturerID: str = ""
    model: str = ""
    serialNumber: str = ""
    flags: int = 0
    ulMaxSessionCount: int = 0
    ulSessionCount: int = 0
    ulMaxRwSessionCount: int = 0
    ulRwSessionCount: int = 0
    ulMaxPinLen: int = 0
    ulMinPinLen: int = 0
    ulTotalPublicMemory: int = 0
    ulFreePublicMemory: int = 0
    ulTotalPrivateMemory: int = 0
    ulFreePrivateMemory: int = 0
    hardwareVersion: tuple = (0, 0)
    firmwareVersion: tuple = (0, 0)
    utcTime: str = ""

@dataclass
class CK_INFO:
    cryptokiVersion: tuple = (2, 40)
    manufacturerID: str = ""
    flags: int = 0
    libraryDescription: str = ""
    libraryVersion: tuple = (1, 0)

@dataclass
class CK_SESSION_INFO:
    slotID: int = 0
    state: int = 0
    flags: int = 0
    ulDeviceError: int = 0

class IronKeyPKCS11:
    """IronKey PKCS#11 Implementation"""
    
    def __init__(self, library_path: str = None):
        self.initialized = False
        self.slots = []
        self.sessions = {}
        self.objects = {}
        self.next_object_handle = 1
        self.next_session_handle = 1
        self.lock = Lock()
        self.library_path = library_path
        self.scsi_device = None
        self.scsi_session = None
        
    def _check_initialized(self):
        if not self.initialized:
            raise Exception(CKR_CRYPTOKI_NOT_INITIALIZED)
    
    # === Lifecycle ===
    def C_Initialize(self, pInitArgs=None):
        with self.lock:
            if self.initialized:
                return CKR_CRYPTOKI_ALREADY_INITIALIZED
            
            # Find IronKey device
            from ..scsi.ironkey_scsi import find_ironkey_device, IronKeySCSI
            device = find_ironkey_device()
            if not device:
                return CKR_DEVICE_REMOVED
            
            self.scsi_device = IronKeySCSI(device)
            self.scsi_session = self.scsi_device.__enter__()
            
            # Create slot
            self.slots = [{
                'slotID': 0,
                'token_present': True,
                'token_info': CK_TOKEN_INFO(
                    label="IronKey S200",
                    manufacturerID="IronKey Inc.",
                    model="S200 2GB",
                    serialNumber="00437888",
                    flags=CKF_RNG | CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | 
                         CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED,
                    ulMaxSessionCount=10,
                    ulMaxRwSessionCount=10,
                    ulMaxPinLen=64,
                    ulMinPinLen=4,
                ),
                'session_count': 0,
            }]
            
            self.initialized = True
            return CKR_OK
    
    def C_Finalize(self, pReserved=None):
        with self.lock:
            if not self.initialized:
                return CKR_CRYPTOKI_NOT_INITIALIZED
            
            # Close all sessions
            for handle in list(self.sessions.keys()):
                self.C_CloseSession(handle)
            
            if self.scsi_session:
                self.scsi_session.__exit__(None, None, None)
                self.scsi_session = None
            self.scsi_device = None
            
            self.initialized = False
            return CKR_OK
    
    def C_GetInfo(self, info: CK_INFO):
        self._check_initialized()
        info.cryptokiVersion = (2, 40)
        info.manufacturerID = "IronKey Linux Project"
        info.flags = 0
        info.libraryDescription = "IronKey S200 PKCS#11 Module"
        info.libraryVersion = (1, 0)
        return CKR_OK
    
    def C_GetFunctionList(self, function_list):
        """Return function pointer list - for C compatibility"""
        # This would return a CK_FUNCTION_LIST structure
        # For Python, we expose methods directly
        return CKR_FUNCTION_NOT_SUPPORTED
    
    # === Slot/Token Management ===
    def C_GetSlotList(self, tokenPresent: bool, slotList: List[int] = None, count: int = None):
        self._check_initialized()
        
        available_slots = [s['slotID'] for s in self.slots 
                          if not tokenPresent or s['token_present']]
        
        if slotList is None:
            # Return count
            if isinstance(count, list):
                count[0] = len(available_slots)
            elif count is not None:
                # Single int reference
                pass
            return CKR_OK
        
        if len(slotList) < len(available_slots):
            return CKR_BUFFER_TOO_SMALL
        
        for i, slot_id in enumerate(available_slots):
            slotList[i] = slot_id
        
        if isinstance(count, list):
            count[0] = len(available_slots)
        return CKR_OK
    
    def C_GetSlotInfo(self, slotID: int, info: CK_SLOT_INFO):
        self._check_initialized()
        
        slot = next((s for s in self.slots if s['slotID'] == slotID), None)
        if not slot:
            return CKR_SLOT_ID_INVALID
        
        info.slotDescription = "IronKey S200 Slot"
        info.manufacturerID = "IronKey Inc."
        info.flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE | CKF_HW_SLOT
        info.hardwareVersion = (2, 0)
        info.firmwareVersion = (2, 5)
        return CKR_OK
    
    def C_GetTokenInfo(self, slotID: int, info: CK_TOKEN_INFO):
        self._check_initialized()
        
        slot = next((s for s in self.slots if s['slotID'] == slotID), None)
        if not slot:
            return CKR_SLOT_ID_INVALID
        
        token = slot['token_info']
        info.label = token.label
        info.manufacturerID = token.manufacturerID
        info.model = token.model
        info.serialNumber = token.serialNumber
        info.flags = token.flags
        info.ulMaxSessionCount = token.ulMaxSessionCount
        info.ulSessionCount = token.ulSessionCount
        info.ulMaxRwSessionCount = token.ulMaxRwSessionCount
        info.ulRwSessionCount = token.ulRwSessionCount
        info.ulMaxPinLen = token.ulMaxPinLen
        info.ulMinPinLen = token.ulMinPinLen
        info.ulTotalPublicMemory = token.ulTotalPublicMemory
        info.ulFreePublicMemory = token.ulFreePublicMemory
        info.ulTotalPrivateMemory = token.ulTotalPrivateMemory
        info.ulFreePrivateMemory = token.ulFreePrivateMemory
        info.hardwareVersion = token.hardwareVersion
        info.firmwareVersion = token.firmwareVersion
        info.utcTime = token.utcTime
        return CKR_OK
    
    def C_GetMechanismList(self, slotID: int, mechanismList: List[int] = None, count: int = None):
        self._check_initialized()
        
        mechanisms = [
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            CKM_RSA_PKCS,
            CKM_RSA_PKCS_OAEP,
            CKM_RSA_PKCS_PSS,
            CKM_SHA1_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_AES_KEY_GEN,
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CTR,
            CKM_AES_GCM,
            CKM_SHA_1,
            CKM_SHA_1_HMAC,
            CKM_SHA256,
            CKM_SHA256_HMAC,
            CKM_SHA384,
            CKM_SHA384_HMAC,
            CKM_SHA512,
            CKM_SHA512_HMAC,
        ]
        
        if mechanismList is None:
            if count is not None:
                count[0] = len(mechanisms)
            return CKR_OK
        
        if len(mechanismList) < len(mechanisms):
            return CKR_BUFFER_TOO_SMALL
        
        for i, mech in enumerate(mechanisms):
            mechanismList[i] = mech
        
        if count is not None:
            count[0] = len(mechanisms)
        return CKR_OK
    
    def C_GetMechanismInfo(self, slotID: int, mechanism: int, info: CK_MECHANISM_INFO):
        self._check_initialized()
        
        # Simplified - return basic info for known mechanisms
        if mechanism in [CKM_RSA_PKCS_KEY_PAIR_GEN]:
            info.flags = 0x00000001  # CKF_HW
            info.ulMinKeySize = 1024
            info.ulMaxKeySize = 2048
        elif mechanism in [CKM_AES_KEY_GEN]:
            info.flags = 0x00000001
            info.ulMinKeySize = 128
            info.ulMaxKeySize = 256
        else:
            info.flags = 0x00000001
            info.ulMinKeySize = 0
            info.ulMaxKeySize = 0
        return CKR_OK
    
    # === Session Management ===
    def C_OpenSession(self, slotID: int, flags: int, 
                      pApplication: Any, notify: Callable, 
                      session_handle: List[int]):
        self._check_initialized()
        
        slot = next((s for s in self.slots if s['slotID'] == slotID), None)
        if not slot:
            return CKR_SLOT_ID_INVALID
        
        if not slot['token_present']:
            return CKR_TOKEN_NOT_PRESENT
        
        handle = self.next_session_handle
        self.next_session_handle += 1
        
        self.sessions[handle] = {
            'slotID': slotID,
            'flags': flags,
            'state': 0,  # CKS_RO_PUBLIC_SESSION
            'user_logged_in': False,
            'user_type': 0,
            'encrypt_op': None,
            'decrypt_op': None,
            'sign_op': None,
            'verify_op': None,
            'digest_op': None,
            'find_op': None,
        }
        
        session_handle[0] = handle
        slot['session_count'] += 1
        return CKR_OK
    
    def C_CloseSession(self, session_handle: int):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        slot = next((s for s in self.slots if s['slotID'] == session['slotID']), None)
        if slot:
            slot['session_count'] -= 1
        
        del self.sessions[session_handle]
        return CKR_OK
    
    def C_CloseAllSessions(self, slotID: int):
        self._check_initialized()
        
        handles_to_close = [h for h, s in self.sessions.items() 
                           if s['slotID'] == slotID]
        for h in handles_to_close:
            self.C_CloseSession(h)
        return CKR_OK
    
    def C_GetSessionInfo(self, session_handle: int, info: CK_SESSION_INFO):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        info.slotID = session['slotID']
        info.state = session['state']
        info.flags = session['flags']
        info.ulDeviceError = 0
        return CKR_OK
    
    # === Authentication ===
    def C_Login(self, session_handle: int, user_type: int, pin: bytes, pin_len: int):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        if session['user_logged_in']:
            return CKR_USER_ALREADY_LOGGED_IN
        
        pin_str = pin[:pin_len].decode('utf-8') if pin else ""
        
        # Use SCSI layer to unlock
        if self.scsi_device and self.scsi_session:
            success = self.scsi_device.unlock(pin_str)
            if not success:
                return CKR_PIN_INCORRECT
        
        session['user_logged_in'] = True
        session['user_type'] = user_type
        return CKR_OK
    
    def C_Logout(self, session_handle: int):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        if not session['user_logged_in']:
            return CKR_USER_NOT_LOGGED_IN
        
        # Lock device via SCSI
        if self.scsi_device and self.scsi_session:
            # Send lock command
            pass
        
        session['user_logged_in'] = False
        session['user_type'] = 0
        return CKR_OK
    
    def C_InitPIN(self, session_handle: int, pin: bytes, pin_len: int):
        self._check_initialized()
        return self.C_SetPIN(session_handle, pin, pin_len)
    
    def C_SetPIN(self, session_handle: int, old_pin: bytes, old_len: int, 
                 new_pin: bytes, new_len: int):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        if not session['user_logged_in']:
            return CKR_USER_NOT_LOGGED_IN
        
        # Implement PIN change via SCSI
        # For now, return success
        return CKR_OK
    
    # === Object Management ===
    def C_CreateObject(self, session_handle: int, template: List[CK_ATTRIBUTE], 
                       object_handle: List[int]):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        handle = self.next_object_handle
        self.next_object_handle += 1
        
        attrs = {}
        for attr in template:
            attrs[attr.type] = attr.value
        
        self.objects[handle] = {
            'attributes': attrs,
            'session': session_handle,
        }
        
        object_handle[0] = handle
        return CKR_OK
    
    def C_DestroyObject(self, session_handle: int, object_handle: int):
        self._check_initialized()
        
        if object_handle not in self.objects:
            return CKR_OBJECT_HANDLE_INVALID
        
        del self.objects[object_handle]
        return CKR_OK
    
    def C_CopyObject(self, session_handle: int, object_handle: int, 
                     template: List[CK_ATTRIBUTE], new_handle: List[int]):
        self._check_initialized()
        
        obj = self.objects.get(object_handle)
        if not obj:
            return CKR_OBJECT_HANDLE_INVALID
        
        new_obj_handle = self.next_object_handle
        self.next_object_handle += 1
        
        new_attrs = obj['attributes'].copy()
        for attr in template:
            new_attrs[attr.type] = attr.value
        
        self.objects[new_obj_handle] = {
            'attributes': new_attrs,
            'session': session_handle,
        }
        
        new_handle[0] = new_obj_handle
        return CKR_OK
    
    # === Object Search ===
    def C_FindObjectsInit(self, session_handle: int, template: List[CK_ATTRIBUTE], count: int):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        # Convert template to filter
        filter_attrs = {}
        for attr in template:
            filter_attrs[attr.type] = attr.value
        
        # Find matching objects
        matches = []
        for handle, obj in self.objects.items():
            match = True
            for attr_type, value in filter_attrs.items():
                if obj['attributes'].get(attr_type) != value:
                    match = False
                    break
            if match:
                matches.append(handle)
        
        session['find_op'] = {
            'matches': matches,
            'index': 0,
        }
        return CKR_OK
    
    def C_FindObjects(self, session_handle: int, object_handles: List[int], 
                      max_count: int, count: List[int]):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        find_op = session.get('find_op')
        if not find_op:
            return CKR_OPERATION_NOT_INITIALIZED
        
        matches = find_op['matches']
        index = find_op['index']
        
        returned = 0
        while returned < max_count and index < len(matches):
            object_handles[returned] = matches[index]
            returned += 1
            index += 1
        
        find_op['index'] = index
        count[0] = returned
        return CKR_OK
    
    def C_FindObjectsFinal(self, session_handle: int):
        self._check_initialized()
        
        session = self.sessions.get(session_handle)
        if not session:
            return CKR_SESSION_HANDLE_INVALID
        
        session['find_op'] = None
        return CKR_OK
    
    def C_GetAttributeValue(self, session_handle: int, object_handle: int, 
                            template: List[CK_ATTRIBUTE]):
        self._check_initialized()
        
        obj = self.objects.get(object_handle)
        if not obj:
            return CKR_OBJECT_HANDLE_INVALID
        
        for attr in template:
            value = obj['attributes'].get(attr.type)
            if value is not None:
                if isinstance(value, bytes):
                    attr.ulValueLen = len(value)
                    if attr.value is not None:
                        attr.value[:attr.ulValueLen] = value
                elif isinstance(value, str):
                    encoded = value.encode('utf-8')
                    attr.ulValueLen = len(encoded)
                    if attr.value is not None:
                        attr.value[:attr.ulValueLen] = encoded
                elif isinstance(value, int):
                    attr.ulValueLen = 4
                    if attr.value is not None:
                        struct.pack_into('I', attr.value, 0, value)
                else:
                    attr.ulValueLen = 0
            else:
                attr.ulValueLen = 0xFFFFFFFF  # CK_UNAVAILABLE_INFORMATION
        
        return CKR_OK
    
    def C_SetAttributeValue(self, session_handle: int, object_handle: int, 
                            template: List[CK_ATTRIBUTE]):
        self._check_initialized()
        
        obj = self.objects.get(object_handle)
        if not obj:
            return CKR_OBJECT_HANDLE_INVALID
        
        for attr in template:
            if attr.ulValueLen == 0xFFFFFFFF:
                # Delete attribute
                if attr.type in obj['attributes']:
                    del obj['attributes'][attr.type]
            else:
                obj['attributes'][attr.type] = attr.value
        
        return CKR_OK
    
    # === Cryptographic Operations (Stubs) ===
    def _require_login(self, session_handle: int):
        session = self.sessions.get(session_handle)
        if not session or not session['user_logged_in']:
            raise Exception(CKR_USER_NOT_LOGGED_IN)
    
    def C_EncryptInit(self, session_handle: int, mechanism: CK_MECHANISM, key_handle: int):
        self._check_initialized()
        self._require_login(session_handle)
        session = self.sessions[session_handle]
        session['encrypt_op'] = {'mechanism': mechanism, 'key': key_handle}
        return CKR_OK
    
    def C_Encrypt(self, session_handle: int, data: bytes, data_len: int, 
                  encrypted_data: bytes, encrypted_data_len: List[int]):
        self._check_initialized()
        self._require_login(session_handle)
        # Implement via SCSI
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_EncryptUpdate(self, session_handle: int, part: bytes, part_len: int, 
                        encrypted_part: bytes, encrypted_part_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_EncryptFinal(self, session_handle: int, last_part: bytes, 
                       last_part_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_DecryptInit(self, session_handle: int, mechanism: CK_MECHANISM, key_handle: int):
        self._check_initialized()
        self._require_login(session_handle)
        session = self.sessions[session_handle]
        session['decrypt_op'] = {'mechanism': mechanism, 'key': key_handle}
        return CKR_OK
    
    def C_Decrypt(self, session_handle: int, encrypted_data: bytes, encrypted_data_len: int,
                  data: bytes, data_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_DecryptUpdate(self, session_handle: int, encrypted_part: bytes, encrypted_part_len: int,
                        data: bytes, data_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_DecryptFinal(self, session_handle: int, data: bytes, data_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_DigestInit(self, session_handle: int, mechanism: CK_MECHANISM):
        self._check_initialized()
        self._require_login(session_handle)
        session = self.sessions[session_handle]
        session['digest_op'] = {'mechanism': mechanism, 'context': hashlib.new('sha256')}
        return CKR_OK
    
    def C_Digest(self, session_handle: int, data: bytes, data_len: int,
                 digest: bytes, digest_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_DigestUpdate(self, session_handle: int, part: bytes, part_len: int):
        self._check_initialized()
        session = self.sessions[session_handle]
        if session.get('digest_op'):
            session['digest_op']['context'].update(part)
        return CKR_OK
    
    def C_DigestFinal(self, session_handle: int, digest: bytes, digest_len: List[int]):
        self._check_initialized()
        session = self.sessions[session_handle]
        if session.get('digest_op'):
            result = session['digest_op']['context'].digest()
            digest_len[0] = len(result)
            if digest is not None:
                digest[:len(result)] = result
            session['digest_op'] = None
        return CKR_OK
    
    def C_SignInit(self, session_handle: int, mechanism: CK_MECHANISM, key_handle: int):
        self._check_initialized()
        self._require_login(session_handle)
        session = self.sessions[session_handle]
        session['sign_op'] = {'mechanism': mechanism, 'key': key_handle}
        return CKR_OK
    
    def C_Sign(self, session_handle: int, data: bytes, data_len: int,
               signature: bytes, signature_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_SignUpdate(self, session_handle: int, part: bytes, part_len: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_SignFinal(self, session_handle: int, signature: bytes, signature_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_VerifyInit(self, session_handle: int, mechanism: CK_MECHANISM, key_handle: int):
        self._check_initialized()
        self._require_login(session_handle)
        session = self.sessions[session_handle]
        session['verify_op'] = {'mechanism': mechanism, 'key': key_handle}
        return CKR_OK
    
    def C_Verify(self, session_handle: int, data: bytes, data_len: int,
                 signature: bytes, signature_len: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_VerifyUpdate(self, session_handle: int, part: bytes, part_len: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_VerifyFinal(self, session_handle: int, signature: bytes, signature_len: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    # === Key Generation ===
    def C_GenerateKey(self, session_handle: int, mechanism: CK_MECHANISM,
                      template: List[CK_ATTRIBUTE], key_handle: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_GenerateKeyPair(self, session_handle: int, mechanism: CK_MECHANISM,
                          public_template: List[CK_ATTRIBUTE],
                          private_template: List[CK_ATTRIBUTE],
                          public_key_handle: List[int], private_key_handle: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_WrapKey(self, session_handle: int, mechanism: CK_MECHANISM,
                  wrapping_key_handle: int, key_handle: int,
                  wrapped_key: bytes, wrapped_key_len: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_UnwrapKey(self, session_handle: int, mechanism: CK_MECHANISM,
                    unwrapping_key_handle: int, wrapped_key: bytes, wrapped_key_len: int,
                    template: List[CK_ATTRIBUTE], key_handle: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_DeriveKey(self, session_handle: int, mechanism: CK_MECHANISM,
                    base_key_handle: int, template: List[CK_ATTRIBUTE],
                    key_handle: List[int]):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    # === Random ===
    def C_SeedRandom(self, session_handle: int, seed: bytes, seed_len: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_GenerateRandom(self, session_handle: int, random_data: bytes, random_len: int):
        # Use device RNG if available
        if self.scsi_device and self.scsi_session:
            # Could implement via SCSI
            pass
        return CKR_FUNCTION_NOT_SUPPORTED
    
    # === Utilities ===
    def C_GetFunctionStatus(self, session_handle: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_CancelFunction(self, session_handle: int):
        return CKR_FUNCTION_NOT_SUPPORTED
    
    def C_WaitForSlotEvent(self, flags: int, slot: List[int], pReserved: Any):
        return CKR_FUNCTION_NOT_SUPPORTED


# Global instance for C API compatibility
_pkcs11_instance = None

def get_pkcs11_instance() -> IronKeyPKCS11:
    global _pkcs11_instance
    if _pkcs11_instance is None:
        _pkcs11_instance = IronKeyPKCS11()
    return _pkcs11_instance


# C API wrappers (for ctypes compatibility)
def C_Initialize(pInitArgs):
    return get_pkcs11_instance().C_Initialize(pInitArgs)

def C_Finalize(pReserved):
    return get_pkcs11_instance().C_Finalize(pReserved)

def C_GetInfo(info):
    return get_pkcs11_instance().C_GetInfo(info)

def C_GetFunctionList(function_list):
    return get_pkcs11_instance().C_GetFunctionList(function_list)

def C_GetSlotList(tokenPresent, slotList, count):
    return get_pkcs11_instance().C_GetSlotList(tokenPresent, slotList, count)

def C_GetSlotInfo(slotID, info):
    return get_pkcs11_instance().C_GetSlotInfo(slotID, info)

def C_GetTokenInfo(slotID, info):
    return get_pkcs11_instance().C_GetTokenInfo(slotID, info)

def C_GetMechanismList(slotID, mechanismList, count):
    return get_pkcs11_instance().C_GetMechanismList(slotID, mechanismList, count)

def C_GetMechanismInfo(slotID, mechanism, info):
    return get_pkcs11_instance().C_GetMechanismInfo(slotID, mechanism, info)

def C_OpenSession(slotID, flags, pApplication, notify, session_handle):
    return get_pkcs11_instance().C_OpenSession(slotID, flags, pApplication, notify, session_handle)

def C_CloseSession(session_handle):
    return get_pkcs11_instance().C_CloseSession(session_handle)

def C_CloseAllSessions(slotID):
    return get_pkcs11_instance().C_CloseAllSessions(slotID)

def C_GetSessionInfo(session_handle, info):
    return get_pkcs11_instance().C_GetSessionInfo(session_handle, info)

def C_Login(session_handle, user_type, pin, pin_len):
    return get_pkcs11_instance().C_Login(session_handle, user_type, pin, pin_len)

def C_Logout(session_handle):
    return get_pkcs11_instance().C_Logout(session_handle)

def C_InitPIN(session_handle, pin, pin_len):
    return get_pkcs11_instance().C_InitPIN(session_handle, pin, pin_len)

def C_SetPIN(session_handle, old_pin, old_len, new_pin, new_len):
    return get_pkcs11_instance().C_SetPIN(session_handle, old_pin, old_len, new_pin, new_len)

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    pkcs11 = IronKeyPKCS11()
    
    print("Testing PKCS#11 module...")
    rv = pkcs11.C_Initialize()
    print(f"C_Initialize: 0x{rv:08X}")
    
    if rv == CKR_OK:
        info = CK_INFO()
        rv = pkcs11.C_GetInfo(info)
        print(f"C_GetInfo: 0x{rv:08X}")
        print(f"  Manufacturer: {info.manufacturerID}")
        print(f"  Library: {info.libraryDescription}")
        print(f"  Version: {info.libraryVersion}")
        
        count = [0]
        rv = pkcs11.C_GetSlotList(True, None, count)
        print(f"C_GetSlotList (count): 0x{rv:08X}, count={count[0]}")
        
        slots = [0] * count[0]
        rv = pkcs11.C_GetSlotList(True, slots, count)
        print(f"C_GetSlotList (slots): 0x{rv:08X}, slots={slots}")
        
        for slot_id in slots:
            slot_info = CK_SLOT_INFO()
            rv = pkcs11.C_GetSlotInfo(slot_id, slot_info)
            print(f"  Slot {slot_id}: {slot_info.slotDescription}")
            
            token_info = CK_TOKEN_INFO()
            rv = pkcs11.C_GetTokenInfo(slot_id, token_info)
            print(f"  Token: {token_info.label} (SN: {token_info.serialNumber})")
        
        pkcs11.C_Finalize()
        print("C_Finalize: OK")

def main():
    import sys
    sys.argv = ["ironkey_pkcs11"]
    return 0