import { NativeModules } from "react-native"
const { RNArgon2 } = NativeModules

const defaultOptions = {
	iterations: 2,
	memory: 32 * 1024,
	parallelism: 1,
	hashLength: 32,
	mode: "argon2id",
	inputEncoding: "utf8", // 'utf8' or 'hex'
	version: 0x13 // 0x10 or 0x13
}

export default async function argon2(password, salt, options = {}) {
	const config = { ...defaultOptions, ...options }

	// 1. Validate existence
	if (!password || !salt) {
		throw new Error("Password and salt are required")
	}
	// 2. Validate version
	if (config.version !== 0x10 && config.version !== 0x13) {
		throw new Error("Invalid Argon2 version. Use 0x10 or 0x13")
	}
	// 3. If using hex encoding, ensure both inputs are valid hex strings with even length
	if (config.inputEncoding === "hex") {
		const hexPattern = /^[0-9a-fA-F]*$/
		if (!hexPattern.test(password) || password.length % 2 !== 0) {
			throw new Error("Invalid hex string for password")
		}
		if (!hexPattern.test(salt) || salt.length % 2 !== 0) {
			throw new Error("Invalid hex string for salt")
		}
	}

	// 4. Call native module with the full config map
	return RNArgon2.argon2(password, salt, {
		iterations: config.iterations,
		memory: config.memory,
		parallelism: config.parallelism,
		hashLength: config.hashLength,
		mode: config.mode,
		// Newly added:
		isHexEncoded: config.inputEncoding === "hex",
		version: config.version
	})
}

export const ArgonEncoding = {
	UTF8: "utf8",
	HEX: "hex"
}

export const ArgonVersion = {
	V10: 0x10,
	V13: 0x13
}

export const ArgonMode = {
	ARGON2D: "argon2d",
	ARGON2I: "argon2i",
	ARGON2ID: "argon2id"
}
