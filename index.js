import { NativeModules } from "react-native"

const { RNArgon2 } = NativeModules

const defaultOptions = {
	iterations: 2,
	memory: 32 * 1024,
	parallelism: 1,
	hashLength: 32,
	mode: "argon2id",
	// New option to specify input encoding
	inputEncoding: "utf8", // 'utf8' or 'hex'
	// New option to specify Argon2 version
	version: 0x13 // 0x10 (v1.0) or 0x13 (v1.3, default)
}

export default async function argon2(password, salt, options = {}) {
	const config = { ...defaultOptions, ...options }

	// Validate inputs
	if (!password || !salt) {
		throw new Error("Password and salt are required")
	}

	// Validate version
	if (config.version !== 0x10 && config.version !== 0x13) {
		throw new Error("Invalid Argon2 version. Use 0x10 or 0x13")
	}

	// Handle hex encoding if specified
	let processedPassword = password
	let processedSalt = salt

	if (config.inputEncoding === "hex") {
		// Validate hex strings
		if (!/^[0-9a-fA-F]*$/.test(password)) {
			throw new Error("Invalid hex string for password")
		}
		if (!/^[0-9a-fA-F]*$/.test(salt)) {
			throw new Error("Invalid hex string for salt")
		}

		// Ensure even length
		if (password.length % 2 !== 0) {
			throw new Error("Hex password must have even length")
		}
		if (salt.length % 2 !== 0) {
			throw new Error("Hex salt must have even length")
		}
	}

	// Pass the encoding type to native modules
	const nativeConfig = {
		...config,
		password: processedPassword,
		salt: processedSalt,
		isHexEncoded: config.inputEncoding === "hex"
	}

	return RNArgon2.argon2(nativeConfig)
}

// Export encoding types for convenience
export const ArgonEncoding = {
	UTF8: "utf8",
	HEX: "hex"
}

// Export version constants for convenience
export const ArgonVersion = {
	V10: 0x10,
	V13: 0x13
}
