/**
 * Options for configuring the Argon2 hashing function.
 */
export interface ArgonOptions {
	/**
	 * Number of iterations (time cost).
	 */
	iterations: number

	/**
	 * Memory cost in kibibytes.
	 */
	memory: number

	/**
	 * Degree of parallelism (number of threads).
	 */
	parallelism: number

	/**
	 * Length of the resulting hash in bytes.
	 */
	hashLength: number

	/**
	 * Argon2 mode. Common values are "argon2d", "argon2i", or "argon2id".
	 */
	mode: string

	/**
	 * Input encoding for password and salt.
	 * - "utf8" if the inputs are UTF-8 strings.
	 * - "hex" if the inputs are hex-encoded.
	 */
	inputEncoding: ArgonEncodingType

	/**
	 * Argon2 version:
	 * - 0x10 (v1.0)
	 * - 0x13 (v1.3)
	 */
	version: ArgonVersionType
}

/**
 * Encoding options for Argon2 inputs.
 */
export type ArgonEncodingType =
	| typeof ArgonEncoding.UTF8
	| typeof ArgonEncoding.HEX

/**
 * Version constants for Argon2.
 */
export type ArgonVersionType = typeof ArgonVersion.V10 | typeof ArgonVersion.V13

/**
 * Asynchronously computes an Argon2 hash for the given password and salt.
 *
 * @param password - The password string (UTF-8 or hex, matching inputEncoding).
 * @param salt - The salt string (UTF-8 or hex, matching inputEncoding).
 * @param options - Optional overrides for the default Argon2 configuration.
 * @returns A promise that resolves to the resulting hash (typically hex-encoded).
 *
 * @throws If password or salt are missing.
 * @throws If an invalid version (not 0x10 or 0x13) is specified.
 * @throws If inputEncoding is "hex" but the provided password/salt are not valid hex strings
 *         (or if their length is not even).
 */
export default function argon2(
	password: string,
	salt: string,
	options?: Partial<ArgonOptions>
): Promise<string>

/**
 * Convenient constants for specifying input encodings.
 */
export const ArgonEncoding: {
	/**
	 * Use UTF-8 encoding for password and salt.
	 */
	UTF8: "utf8"

	/**
	 * Use hexadecimal encoding for password and salt.
	 */
	HEX: "hex"
}

/**
 * Convenient constants for specifying Argon2 versions.
 */
export const ArgonVersion: {
	/**
	 * Argon2 version 1.0 (0x10).
	 */
	V10: 0x10

	/**
	 * Argon2 version 1.3 (0x13).
	 */
	V13: 0x13
}
