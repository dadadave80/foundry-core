// C-ABI shim over CryptoKit's Secure Enclave API for the `touch-id` feature.
//
// Persisting a Secure Enclave key without keychain entitlements is only possible
// through CryptoKit's `dataRepresentation` (an enclave-encrypted, device-bound
// blob), which has no C or Objective-C surface — hence this Swift file, compiled
// and linked by this crate's build script.
//
// Scheme (the `age-plugin-se` pattern): an enclave-resident P-256 key wraps a
// secret via ECIES (ephemeral P-256 ECDH + HKDF-SHA256 + ChaChaPoly). Wrapping
// uses only the public key and never prompts; unwrapping performs the ECDH
// inside the enclave, which enforces the key's access-control policy (Touch ID).
//
// All functions return 0 on success. On failure they return 1 and, when the out
// parameters are provided, place a malloc'd UTF-8 error message in them. Output
// buffers are malloc'd and must be released with `foundry_se_free`.

import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

private let hkdfInfo = Data("foundry-touch-id-v1".utf8)
private let x963PublicKeyLen = 65
private let chaChaPolyOverheadLen = 12 + 16  // nonce + tag

private func setOut(
    _ bytes: Data,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) {
    // `!` traps deterministically on allocation failure, even under -O.
    let buf = malloc(bytes.count)!.assumingMemoryBound(to: UInt8.self)
    bytes.copyBytes(to: buf, count: bytes.count)
    outPtr.pointee = buf
    outLen.pointee = bytes.count
}

private func fail(
    _ message: String,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    setOut(Data(message.utf8), outPtr, outLen)
    return 1
}

private func accessControl(policy: Int32) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    switch policy {
    case 1: flags.insert(.userPresence)
    case 2: flags.insert(.biometryCurrentSet)
    default: break
    }
    var error: Unmanaged<CFError>?
    guard
        let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
    else {
        throw error!.takeRetainedValue() as Error
    }
    return ac
}

private func deriveKey(
    _ shared: SharedSecret, _ ephemeralPub: P256.KeyAgreement.PublicKey,
    _ recipientPub: P256.KeyAgreement.PublicKey
) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeralPub.x963Representation + recipientPub.x963Representation,
        sharedInfo: hkdfInfo,
        outputByteCount: 32)
}

@_cdecl("foundry_se_available")
public func foundrySeAvailable() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

@_cdecl("foundry_se_create")
public func foundrySeCreate(
    _ policy: Int32,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        return fail("Secure Enclave is not available on this machine", outPtr, outLen)
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: accessControl(policy: policy))
        setOut(key.dataRepresentation, outPtr, outLen)
        return 0
    } catch {
        return fail("failed to create Secure Enclave key: \(error)", outPtr, outLen)
    }
}

@_cdecl("foundry_se_wrap")
public func foundrySeWrap(
    _ blobPtr: UnsafePointer<UInt8>, _ blobLen: Int,
    _ plainPtr: UnsafePointer<UInt8>, _ plainLen: Int,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blobPtr, count: blobLen))
        let recipientPub = key.publicKey
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipientPub)
        let symKey = deriveKey(shared, ephemeral.publicKey, recipientPub)
        let sealed = try ChaChaPoly.seal(Data(bytes: plainPtr, count: plainLen), using: symKey)
        setOut(ephemeral.publicKey.x963Representation + sealed.combined, outPtr, outLen)
        return 0
    } catch {
        return fail("failed to wrap secret: \(error)", outPtr, outLen)
    }
}

@_cdecl("foundry_se_unwrap")
public func foundrySeUnwrap(
    _ blobPtr: UnsafePointer<UInt8>, _ blobLen: Int,
    _ sealedPtr: UnsafePointer<UInt8>, _ sealedLen: Int,
    _ reasonPtr: UnsafePointer<CChar>?,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard sealedLen >= x963PublicKeyLen + chaChaPolyOverheadLen else {
        return fail("sealed data is truncated", outPtr, outLen)
    }
    do {
        let context = LAContext()
        if let reasonPtr {
            context.localizedReason = String(cString: reasonPtr)
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blobPtr, count: blobLen),
            authenticationContext: context)
        let sealed = Data(bytes: sealedPtr, count: sealedLen)
        let ephemeralPub = try P256.KeyAgreement.PublicKey(
            x963Representation: sealed.prefix(x963PublicKeyLen))
        // The enclave evaluates the key's access-control policy here (Touch ID).
        let shared = try key.sharedSecretFromKeyAgreement(with: ephemeralPub)
        let symKey = deriveKey(shared, ephemeralPub, key.publicKey)
        let box = try ChaChaPoly.SealedBox(combined: sealed.dropFirst(x963PublicKeyLen))
        setOut(try ChaChaPoly.open(box, using: symKey), outPtr, outLen)
        return 0
    } catch {
        return fail("failed to unwrap secret: \(error)", outPtr, outLen)
    }
}

@_cdecl("foundry_se_free")
public func foundrySeFree(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int) {
    if let ptr, len > 0 {
        // Buffers may hold the plaintext keystore password; scrub before freeing.
        memset_s(ptr, len, 0, len)
    }
    free(ptr)
}
