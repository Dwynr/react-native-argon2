import Foundation
import Argon2

@objc(RNArgon2)
class RNArgon2: NSObject {
    
    @objc
    func argon2(_ config: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        
        guard let passwordString = config["password"] as? String,
              let saltString = config["salt"] as? String else {
            reject("EINVAL", "Password and salt are required", nil)
            return
        }
        
        let iterations = config["iterations"] as? Int ?? 2
        let memory = config["memory"] as? Int ?? 32768
        let parallelism = config["parallelism"] as? Int ?? 1
        let hashLength = config["hashLength"] as? Int ?? 32
        let mode = config["mode"] as? String ?? "argon2id"
        let isHexEncoded = config["isHexEncoded"] as? Bool ?? false
        let version = config["version"] as? Int ?? 0x13
        
        // Note: CatCrypto may not support version selection
        // If it doesn't, you might need to use a different Argon2 library
        // or accept that iOS will always use the default version
        if version != 0x13 {
            print("Warning: CatCrypto may not support Argon2 version selection. Using default version.")
        }
        
        // Convert inputs based on encoding
        let passwordData: Data
        let saltData: Data
        
        if isHexEncoded {
            guard let pwdData = hexStringToData(passwordString),
                  let sltData = hexStringToData(saltString) else {
                reject("EINVAL", "Invalid hex encoding", nil)
                return
            }
            passwordData = pwdData
            saltData = sltData
        } else {
            passwordData = passwordString.data(using: .utf8)!
            saltData = saltString.data(using: .utf8)!
        }
        
        // Set Argon2 mode
        let argonMode: Argon2Mode
        switch mode {
        case "argon2i":
            argonMode = .argon2i
        case "argon2d":
            argonMode = .argon2d
        default:
            argonMode = .argon2id
        }
        
        // Perform hashing
        do {
            let result = try Argon2.hash(
                password: passwordData,
                salt: saltData,
                iterations: iterations,
                memory: memory,
                parallelism: parallelism,
                length: hashLength,
                mode: argonMode
            )
            
            let response: [String: String] = [
                "rawHash": result.hashData.hexEncodedString(),
                "encodedHash": result.encodedString
            ]
            
            resolve(response)
        } catch {
            reject("EHASH", "Hashing failed: \(error.localizedDescription)", error)
        }
    }
    
    // Helper function to convert hex string to Data
    private func hexStringToData(_ hex: String) -> Data? {
        var data = Data()
        var hex = hex
        
        // Remove spaces and ensure even length
        hex = hex.replacingOccurrences(of: " ", with: "")
        
        guard hex.count % 2 == 0 else { return nil }
        
        for i in stride(from: 0, to: hex.count, by: 2) {
            let start = hex.index(hex.startIndex, offsetBy: i)
            let end = hex.index(hex.startIndex, offsetBy: i + 2)
            let bytes = hex[start..<end]
            
            if let byte = UInt8(bytes, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
        }
        
        return data
    }
    
    @objc
    static func requiresMainQueueSetup() -> Bool {
        return false
    }
}

// Extension to convert Data to hex string
extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}