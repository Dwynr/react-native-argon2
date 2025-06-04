import Foundation
import CatCrypto // CatCrypto’s Argon2 binding :contentReference[oaicite:20]{index=20}
import React

@objc(RNArgon2)
class RNArgon2: NSObject {

  @objc
  static func requiresMainQueueSetup() -> Bool {
    return true
  }

  @objc(argon2:resolver:rejecter:)
  func argon2(
    _ password: String,
    salt: String,
    config: NSDictionary? = nil,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) -> Void {
    // 1. Convert NSDictionary to Swift Dictionary<String,Any> (or empty)
    let configDict = config as? [String:Any] ?? [:]

    // 2. Detect hex-encoding flag (default = false → UTF-8) :contentReference[oaicite:21]{index=21}
    let isHexEncoded = configDict["isHexEncoded"] as? Bool ?? false

    // 3. Read JS-passed version (0x10 or 0x13, default = 0x13) :contentReference[oaicite:22]{index=22}
    let jsVersion = configDict["version"] as? Int ?? 0x13
    guard jsVersion == 0x10 || jsVersion == 0x13 else {
      reject("E_INVALID_VERSION", "Invalid Argon2 version. Use 0x10 or 0x13", nil)
      return
    }
    // CatCrypto expects 16 for 0x10, 19 for 0x13 :contentReference[oaicite:23]{index=23}
    let catVersion: Int = (jsVersion == 0x10) ? 16 : 19

    // 4. Read other Argon2 parameters (default values match upstream) :contentReference[oaicite:24]{index=24}
    let iterations  = configDict["iterations"]  as? Int ?? 2
    let memory      = configDict["memory"]      as? Int ?? (32 * 1024)
    let parallelism = configDict["parallelism"] as? Int ?? 1
    let hashLength  = configDict["hashLength"]  as? Int ?? 32
    let modeString  = (configDict["mode"] as? String ?? "argon2id").lowercased()

    // 5. Convert password & salt into Data, depending on encoding :contentReference[oaicite:25]{index=25}
    let passwordData: Data
    let saltData: Data
    if isHexEncoded {
      // a) Validate that both strings are valid hex & even-length :contentReference[oaicite:26]{index=26}
      let hexSet = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
      guard password.count % 2 == 0,
            salt.count   % 2 == 0,
            CharacterSet(charactersIn: password).isSubset(of: hexSet),
            CharacterSet(charactersIn: salt).isSubset(of: hexSet),
            let pwdBytes  = Data(hexString: password),
            let saltBytes = Data(hexString: salt) else {
        reject("E_INVALID_HEX", "Invalid hex string for password or salt", nil)
        return
      }
      passwordData = pwdBytes
      saltData     = saltBytes
    } else {
      // Treat as UTF-8 :contentReference[oaicite:27]{index=27}
      guard let pwdBytes  = password.data(using: .utf8),
            let saltBytes = salt.data(using: .utf8) else {
        reject("E_UTF8_ENCODE_FAILED", "Failed to convert password/salt to UTF-8", nil)
        return
      }
      passwordData = pwdBytes
      saltData     = saltBytes
    }

    // 6. Map mode string to CatArgon2Mode enum :contentReference[oaicite:28]{index=28}
    let argonType: CatArgon2Mode
    switch modeString {
      case "argon2d":  argonType = .argon2d
      case "argon2i":  argonType = .argon2i
      case "argon2id": argonType = .argon2id
      default:
        reject("E_INVALID_MODE", "Invalid Argon2 mode. Use argon2d, argon2i, or argon2id", nil)
        return
    }

    // 7. Build CatArgon2Context with new version and other parameters :contentReference[oaicite:29]{index=29}
    let argon2Context = CatArgon2Context.init()
    argon2Context.iterations  = iterations
    argon2Context.memory      = memory
    argon2Context.parallelism = parallelism
    argon2Context.hashLength  = hashLength
    argon2Context.mode        = argonType
    argon2Context.version     = catVersion // ← ADDED: tell CatCrypto whether to use v1.0 (16) or v1.3 (19)

    // 8. Compute the encoded (PHC) hash first
    let argon2Crypto = CatArgon2Crypto.init(context: argon2Context)
    let encodedResult = argon2Crypto.hash(password: passwordData, salt: saltData)

    // 9. Switch to raw-hash output and hash again
    argon2Crypto.context.hashResultType = .hashRaw
    let rawResult = argon2Crypto.hash(password: passwordData, salt: saltData)

    // 10. Check for any errors :contentReference[oaicite:30]{index=30}
    if rawResult.error != nil || encodedResult.error != nil {
      let error = NSError(domain: "com.dwynr.argon2", code: 200, userInfo: [
        "Error reason": "Failed to generate argon2 hash"
      ])
      reject("E_ARGON2", "Failed to generate argon2 hash", error)
      return
    }

    // 11. Convert raw hash bytes to hex string :contentReference[oaicite:31]{index=31}
    let rawHash     = rawResult.hexStringValue()
    let encodedHash = encodedResult.stringValue()

    // 12. Return both rawHash and encodedHash to JS :contentReference[oaicite:32]{index=32}
    let resultDictionary: NSDictionary = [
      "rawHash"     : rawHash,
      "encodedHash" : encodedHash
    ]
    resolve(resultDictionary)
  }

  func getArgon2Mode(mode: String) -> CatArgon2Mode {
    var selectedMode: CatArgon2Mode
    switch mode {
      case "argon2d":
        selectedMode = CatArgon2Mode.argon2d
      case "argon2i":
        selectedMode = CatArgon2Mode.argon2i
      case "argon2id":
        selectedMode = CatArgon2Mode.argon2id
      default:
        selectedMode = CatArgon2Mode.argon2id
    }
    return selectedMode
  }
}

// MARK: – Data extension to decode hex strings :contentReference[oaicite:33]{index=33}
fileprivate extension Data {
  /// Initialize Data from a hex string (e.g., "deadbeef").
  init?(hexString: String) {
    var data = Data(capacity: hexString.count / 2)
    var index = hexString.startIndex
    for _ in 0 ..< hexString.count / 2 {
      let nextIndex = hexString.index(index, offsetBy: 2)
      let byteString = hexString[index..<nextIndex]
      if let num = UInt8(byteString, radix: 16) {
        data.append(num)
      } else {
        return nil
      }
      index = nextIndex
    }
    self = data
  }
}
