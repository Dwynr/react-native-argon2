package com.dwynr.argon2;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import com.lambdapioneer.argon2kt.Argon2Kt;
import com.lambdapioneer.argon2kt.Argon2KtResult;
import com.lambdapioneer.argon2kt.Argon2Mode;
import com.lambdapioneer.argon2kt.Argon2Version;

import java.nio.charset.StandardCharsets;

public class RNArgon2Module extends ReactContextBaseJavaModule {
    
    private final ReactApplicationContext reactContext;
    private final Argon2Kt argon2;
    
    public RNArgon2Module(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
        this.argon2 = new Argon2Kt();
    }
    
    @Override
    public String getName() {
        return "RNArgon2";
    }
    
    @ReactMethod
    public void argon2(ReadableMap config, Promise promise) {
        try {
            String passwordString = config.getString("password");
            String saltString = config.getString("salt");
            
            if (passwordString == null || saltString == null) {
                promise.reject("EINVAL", "Password and salt are required");
                return;
            }
            
            // Read configuration
            int iterations = config.hasKey("iterations") ? config.getInt("iterations") : 2;
            int memory = config.hasKey("memory") ? config.getInt("memory") : 32768;
            int parallelism = config.hasKey("parallelism") ? config.getInt("parallelism") : 1;
            int hashLength = config.hasKey("hashLength") ? config.getInt("hashLength") : 32;
            String mode = config.hasKey("mode") ? config.getString("mode") : "argon2id";
            boolean isHexEncoded = config.hasKey("isHexEncoded") ? config.getBoolean("isHexEncoded") : false;
            int version = config.hasKey("version") ? config.getInt("version") : 0x13;
            
            // Convert inputs based on encoding
            byte[] passwordBytes;
            byte[] saltBytes;
            
            if (isHexEncoded) {
                passwordBytes = hexStringToByteArray(passwordString);
                saltBytes = hexStringToByteArray(saltString);
                
                if (passwordBytes == null || saltBytes == null) {
                    promise.reject("EINVAL", "Invalid hex encoding");
                    return;
                }
            } else {
                passwordBytes = passwordString.getBytes(StandardCharsets.UTF_8);
                saltBytes = saltString.getBytes(StandardCharsets.UTF_8);
            }
            
            // Set Argon2 mode
            Argon2Mode argonMode;
            switch (mode) {
                case "argon2i":
                    argonMode = Argon2Mode.ARGON2_I;
                    break;
                case "argon2d":
                    argonMode = Argon2Mode.ARGON2_D;
                    break;
                default:
                    argonMode = Argon2Mode.ARGON2_ID;
                    break;
            }
            
            // Set Argon2 version
            Argon2Version argonVersion;
            switch (version) {
                case 0x10:
                    argonVersion = Argon2Version.V10;
                    break;
                case 0x13:
                    argonVersion = Argon2Version.V13;
                    break;
                default:
                    promise.reject("EINVAL", "Invalid Argon2 version. Use 0x10 or 0x13");
                    return;
            }
            
            // Perform hashing
            Argon2KtResult result = argon2.hash(
                argonMode,
                passwordBytes,
                saltBytes,
                iterations,
                memory,
                parallelism,
                hashLength,
                argonVersion
            );
            
            // Prepare response
            WritableMap response = new WritableNativeMap();
            response.putString("rawHash", bytesToHex(result.rawHashAsByteArray()));
            response.putString("encodedHash", result.encodedOutputAsString());
            
            promise.resolve(response);
            
        } catch (Exception e) {
            promise.reject("EHASH", "Hashing failed: " + e.getMessage(), e);
        }
    }
    
    // Helper method to convert hex string to byte array
    private byte[] hexStringToByteArray(String hex) {
        hex = hex.replaceAll("\\s", ""); // Remove spaces
        
        if (hex.length() % 2 != 0) {
            return null;
        }
        
        int len = hex.length();
        byte[] data = new byte[len / 2];
        
        try {
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                   + Character.digit(hex.charAt(i + 1), 16));
            }
            return data;
        } catch (Exception e) {
            return null;
        }
    }
    
    // Helper method to convert byte array to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}