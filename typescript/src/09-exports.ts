// ---------------------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------------------

export { SsencError, encrypt, decrypt, decryptToString, rekey, inspect, detectMode, setKdfCacheSize, VERSION, BUILD };
export { sshParsePublicKey, sshFingerprint, sshKeyType };
export type { SsencErrorKind, Key, PasswordKey, SshKey, SshSigner, EncryptOptions, RekeyOptions, InspectResult, SlotInfo, KdfParams };
