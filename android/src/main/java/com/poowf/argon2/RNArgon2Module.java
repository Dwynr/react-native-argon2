package com.dwynr.argon2;

import android.app.Activity;
import android.content.Intent;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.bridge.Promise;

import com.lambdapioneer.argon2kt.Argon2Kt;
import com.lambdapioneer.argon2kt.Argon2KtResult;
import com.lambdapioneer.argon2kt.Argon2Mode;

import java.nio.charset.StandardCharsets; // for UTF-8 encoding :contentReference[oaicite:0]{index=0}
import java.util.regex.Pattern;           // for validating hex strings :contentReference[oaicite:1]{index=1}

public class RNArgon2Module extends ReactContextBaseJavaModule {
    private ReactContext mReactContext;

    public RNArgon2Module(ReactApplicationContext reactContext) {
        super(reactContext);
        mReactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNArgon2";
    }

    // Regular expression to validate that a string contains only hex characters (0–9, a–f, A–F) :contentReference[oaicite:2]{index=2}
    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]+$");

    @ReactMethod
    public void argon2(
        String password,
        String salt,
        ReadableMap config,
        Promise promise
    ) {
        try {
            // 1. Check whether inputs are hex-encoded or UTF-8 (default = false → UTF-8) :contentReference[oaicite:3]{index=3}
            boolean isHexEncoded = config.hasKey("isHexEncoded") && config.getBoolean("isHexEncoded");

            // 2. Read Argon2 version from JS (0x10 or 0x13); default = 0x13 :contentReference[oaicite:4]{index=4}
            int jsVersion = config.hasKey("version") ? config.getInt("version") : 0x13;
            if (jsVersion != 0x10 && jsVersion != 0x13) {
                promise.reject("E_INVALID_VERSION", "Invalid Argon2 version. Use 0x10 or 0x13");
                return;
            }
            // Map 0x10 → 16 and 0x13 → 19, as Argon2Kt expects those integer constants :contentReference[oaicite:5]{index=5}
            int nativeVersion = (jsVersion == 0x10) ? 16 : 19;

            // 3. Decode password and salt into byte[]; either hex decode or UTF-8 encode :contentReference[oaicite:6]{index=6}
            byte[] passwordBytes;
            byte[] saltBytes;
            if (isHexEncoded) {
                // a) Validate that both strings are valid hex and have even length :contentReference[oaicite:7]{index=7}
                if (!HEX_PATTERN.matcher(password).matches() || (password.length() % 2 != 0)
                 || !HEX_PATTERN.matcher(salt).matches()   || (salt.length() % 2 != 0)) {
                    promise.reject("E_INVALID_HEX", "Invalid hex string for password or salt");
                    return;
                }
                // b) Convert each pair of hex chars into one byte :contentReference[oaicite:8]{index=8}
                passwordBytes = hexToBytes(password);
                saltBytes     = hexToBytes(salt);
            } else {
                // Treat strings as UTF-8 :contentReference[oaicite:9]{index=9}
                passwordBytes = password.getBytes(StandardCharsets.UTF_8);
                saltBytes     = salt.getBytes(StandardCharsets.UTF_8);
            }

            // 4. Read the remaining Argon2 parameters (iteration count, memory size, etc.) :contentReference[oaicite:10]{index=10}
            Integer iterations  = config.hasKey("iterations")  ? config.getInt("iterations")  : 2;
            Integer memory      = config.hasKey("memory")      ? config.getInt("memory")      : (32 * 1024);
            Integer parallelism = config.hasKey("parallelism") ? config.getInt("parallelism") : 1;
            Integer hashLength  = config.hasKey("hashLength")  ? config.getInt("hashLength")  : 32;
            Argon2Mode mode      = config.hasKey("mode")
                                      ? getArgon2Mode(config.getString("mode"))
                                      : Argon2Mode.ARGON2_ID;

            // 5. Create Argon2Kt instance and override its version to match JS input :contentReference[oaicite:11]{index=11}
            final Argon2Kt argon2Kt = new Argon2Kt();
            argon2Kt.setVersion(nativeVersion);

            // 6. Perform the Argon2 hash operation :contentReference[oaicite:12]{index=12}
            final Argon2KtResult hashResult = argon2Kt.hash(
                    mode,
                    passwordBytes,
                    saltBytes,
                    iterations,
                    memory,
                    parallelism,
                    hashLength);
            final String rawHash     = hashResult.rawHashAsHexadecimal(false);
            final String encodedHash = hashResult.encodedOutputAsString();

            // 7. Build the result map and resolve the promise :contentReference[oaicite:13]{index=13}
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putString("rawHash", rawHash);
            resultMap.putString("encodedHash", encodedHash);
            promise.resolve(resultMap);

        } catch (Exception exception) {
            promise.reject("E_ARGON2_FAILED", exception);
        }
    }

    public Argon2Mode getArgon2Mode(String mode) {
        Argon2Mode selectedMode;
        switch (mode) {
            case "argon2d":
                selectedMode = Argon2Mode.ARGON2_D;
                break;
            case "argon2i":
                selectedMode = Argon2Mode.ARGON2_I;
                break;
            case "argon2id":
                selectedMode = Argon2Mode.ARGON2_ID;
                break;
            default:
                selectedMode = Argon2Mode.ARGON2_ID;
                break;
        }
        return selectedMode;
    }

    //──────────────────────────────────────────────────────────────────────────
    // Helper: Convert a hex string (e.g., "deadbeef") into a byte[] :contentReference[oaicite:14]{index=14}
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                               +  Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
