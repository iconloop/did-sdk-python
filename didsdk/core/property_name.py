class PropertyName:
    ALGO_KEY_RSA = "RS256"
    ALGO_KEY_ECDSA = "ES256"
    ALGO_KEY_ECDSAK = "ES256K"

    ALGO_KEYTYPE_ECDSA = "EC"

    EC_CURVE_PARAM_SECP256R1 = "secp256r1"
    EC_CURVE_PARAM_SECP256K1 = "secp256k1"

    KEY_DOCUMENT_CONTEXT = "@context"
    KEY_VERSION = "version"
    KEY_DOCUMENT_ID = "id"
    KEY_DOCUMENT_CREATED = "created"
    KEY_DOCUMENT_UPDATED = "updated"
    KEY_DOCUMENT_PUBLICKEY = "publicKey"
    KEY_DOCUMENT_PUBLICKEY_ID = "id"
    KEY_DOCUMENT_PUBLICKEY_TYPE = "type"
    KEY_DOCUMENT_PUBLICKEY_HEX = "publicKeyHex"
    KEY_DOCUMENT_PUBLICKEY_BASE64 = "publicKeyBase64"
    KEY_DOCUMENT_PUBLICKEY_CREATED = "created"
    KEY_DOCUMENT_PUBLICKEY_REVOKED = "revoked"
    KEY_DOCUMENT_AUTHENTICATION = "authentication"
    KEY_DOCUMENT_AUTHENTICATION_PUBLICKEY = "publicKey"
    KEY_DOCUMENT_AUTHENTICATION_TYPE = "type"

    VALUE_DOCUMENT_CONTEXT = "https://w3id.org/did/v1"

    # Update Transaction
    KEY_TX_UPDATE_METHOD = "method"
    KEY_TX_UPDATE_METHOD_ADDKEY = "addKey"
    KEY_TX_UPDATE_METHOD_REVOKEKEY = "revokeKey"
    KEY_TX_UPDATE_PARAM = "param"

    # 1.1
    KEY_PROTOCOL_TYPE = "type"
    KEY_PROTOCOL_MESSAGE = "message"
    KEY_PROTOCOL_PARAM = "param"
    KEY_PROTOCOL_PROTECTED = "protected"
    KEY_PROTOCOL_PUBLICKEY = "publicKey"
    KEY_PROTOCOL_PUBLICKEY_KID = "kid"
    KEY_PROTOCOL_PUBLICKEY_EPK = "epk"

    # JWE
    JWE_KEY_TYPE = "kty"
    JWE_CURVE = "crv"
    JWE_X = "x"
    JWE_Y = "y"
    JWE_D = "d"

    JWE_KEY_ID = "kid"
    JWE_EPERMERAL_PUBLIC_KEY = "epk"
    JWE_ALGORITHM = "alg"
    JWE_ENC_METHOD = "enc"

    # 2.0 JSON-LD
    # vc
    JL_CONTEXT = "@context"
    JL_ID = "id"
    JL_AT_ID = "@id"
    JL_CRYPTO_TYPE = "cryptoType"
    JL_CRYPTO_ALGORITHM = "cryptoAlgorithm"
    JL_CREDENTIAL_SUBJECT = "credentialSubject"
    JL_REFRESH_SERVICE = "refreshService"
    JL_REVOCATION_SERVICE = "revocationService"
    JL_TERMS_OF_USE = "termsOfUse"
    JL_TYPE_VERIFIABLE_CREDENTIAL = "VerifiableCredential"

    # param
    JL_CREDENTIAL_PARAM = "credentialParam"
    JL_CLAIM_VALUE = "claimValue"
    JL_CLAIM_SALT = "claimSalt"
    JL_CLAIM = "claim"
    JL_INFO = "info"
    JL_SALT = "salt"
    JL_DISPLAY_VALUE = "displayValue"
    JL_DISPLAY_LAYOUT = "displayLayout"
    JL_PROOF_TYPE = "proofType"
    JL_HASH_ALGORITHM = "hashAlgorithm"

    # vp
    JL_PRESENTER = "presenter"
    JL_FULFILLED_CRITERIA = "fulfilledCriteria"
    JL_TYPE = "type"
    JL_CONDITION_ID = "conditionId"
    JL_VERIFIABLE_CREDENTIAL = "verifiableCredential"
    JL_VERIFIABLE_CREDENTIAL_PARAM = "verifiableCredentialParam"
    JL_TYPE_CREDENTIAL_PARAM = "CredentialParam"

    # vpr
    JL_AT_TYPE = "@type"
    JL_PRESENTATION_URL = "presentationUrl"
    JL_PRESENTATION_REQUEST = "presentationRequest"
    JL_PURPOSE = "purpose"
    JL_PURPOSE_LABEL = "purposeLabel"
    JL_VERIFIER = "verifier"
    JL_CONDITION = "condition"
    JL_ISSUER = "issuer"
    JL_OPERATOR = "operator"
    JL_PROPERTY = "property"
    JL_CREDENTIAL_TYPE = "credentialType"

    # vcr
    JL_REQUEST_CLAIM = "requestClaim"
