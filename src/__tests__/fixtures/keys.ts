/**
 * Throwaway test keys. They protect nothing and exist only to test the key format parsers.
 *
 * Every key below is the same Ed25519 key (seed = SEED_HEX) written by a different tool: OpenSSL 3.0 / Node's crypto
 * (PKCS#8, SPKI, JWK) and Python's cryptography (OpenSSH). The `wrong*` entries are keys of another type or encrypted.
 * RFC8410 is the example private key of RFC 8410, section 10.3.
 */

export const SEED_HEX = "02efa9afb1304eaa4d10638c933dece519c39ee9ce9e10d8093d218ee799217a";
export const PUBLIC_HEX = "5f82d54a68d23979e9756866b6b90ce277ef34e1d5daec3871c5409d56351a8d";
export const PKCS8_PEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIALvqa+xME6qTRBjjJM97OUZw57pzp4Q2Ak9IY7nmSF6\n-----END PRIVATE KEY-----\n";
export const SPKI_PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0=\n-----END PUBLIC KEY-----\n";
export const OPENSSH_PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\nc2gtZWQyNTUxOQAAACBfgtVKaNI5eel1aGa2uQzid+804dXa7DhxxUCdVjUajQAA\nAIjeMuSA3jLkgAAAAAtzc2gtZWQyNTUxOQAAACBfgtVKaNI5eel1aGa2uQzid+80\n4dXa7DhxxUCdVjUajQAAAEAC76mvsTBOqk0QY4yTPezlGcOe6c6eENgJPSGO55kh\nel+C1Upo0jl56XVoZra5DOJ37zTh1drsOHHFQJ1WNRqNAAAAAAECAwQF\n-----END OPENSSH PRIVATE KEY-----\n";
export const OPENSSH_PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+C1Upo0jl56XVoZra5DOJ37zTh1drsOHHFQJ1WNRqN test@example";
export const JWK_PRIVATE = "{\"crv\":\"Ed25519\",\"d\":\"Au-pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo\",\"x\":\"X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0\",\"kty\":\"OKP\"}";
export const JWK_PUBLIC = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0\"}";
export const RFC8410 = {"pem": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n", "seedHex": "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842", "publicHex": "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"};

export const WRONG = {
    x25519Pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIEhIU4j1F7VlBrrxouw/cj9t18hJs7ogGLEsoZy5X9Ri\n-----END PRIVATE KEY-----\n",
    ed448Pem: "-----BEGIN PRIVATE KEY-----\nMEcCAQAwBQYDK2VxBDsEOWkGn3NL9C5uMC20VSNAdVwAUqGaxJxISUfd/+ucQGgK\n6x5s9Q6192atl3li9an9kVCragKn7+VnDw==\n-----END PRIVATE KEY-----\n",
    ecPem: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8DeFslR+rJgKxLvg\nwNpw0E7OOmX+voMZTPkZIWgflgihRANCAARNVxbtBY+IeU4/+mKliazyxKv08nwL\nk1x5NHtkAloE1fwBLquGFT+9V1TlrvRC+LpYSHSDzR4HVk0AR4N3AuA/\n-----END PRIVATE KEY-----\n",
    rsaPem: "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM2LKrKs72fw1FFb\nlHVY7kIrRqmYcpH7vkR1zb+CD5MMmvc7BboRjq9i4o9mRqSmVASTAz3kqfK30+Rl\n95DkmnKiiphzkzN0sTPgwbV+SgHj5BzVBD+sBGC3lAQIHaoVDXSfPbz5bnR+2UPU\nd2VnryT16AYjZ/5Fgfaa28d2ANwrAgMBAAECgYEAzBHOq6Ts8Gp3serVw4guzX0/\n4+PaZDvn1PqM8wVDR0DtnmZ4Mht6aYEo5SyrGI+WvQ/k2Q9s9/ExLANcvvtopn3i\n11aAvh4c2v4jjnbcDZijK9JmZrLgJwi3qfvmyO5bsPZW5qEF1qOUKsrCF/noEmEU\nETNcLAv8bg1nJnV43fECQQDwWJ+bsOKhIxhE1+G4hHV5AFixYTRz6yZL5GeX2itg\nKa1Rdgeq61hKDBGZs2fi2GSdgnNpzivjXFKrV73GLDEzAkEA2u5ElUw/RovNR2p5\n26ETJAQoBQzI1zbh1oeniQcYN/xT9W79zmj0oOBjBDgsoylBNVPhB6Fm3QJAD7XR\nBWUZKQJASRyscM/+IMZsO4TwRREGKyjP0iWfryN5Itz4JllXmIkVEBK3gmbVFLFX\nKUpJ79ejw8ZLFYSCFUegXj7ym7YVwQJAS6nxdg/mBoGmrrnz554huV7eXfBvMUI8\nhyJXGpqjGiZQ9hAoE8BeW4NxdTHc638ElGOq8DIuFNAER+m0lcK9EQJBAIE7bWRg\nCbgxLRDMPNOGVa8VBtrS0Cxx4HQAi8ReV3c9ikVczgkb5d3G8NSCiF57draI69fk\nD9RGDjHRn5+q9XM=\n-----END PRIVATE KEY-----\n",
    rsaPublicPem: "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiPTEBchM45IMGLH4t+CDNHKQw\ngseyCGWSSsahMdGnjmzVfToiiN35GSLEsSPdKXb9bj76JoxVkLrO4F7VnkGgOI/4\nXx0jnGA6HHextWsYJdRxH2I5Qm8wUzAeuvTPwtulpnGhVatdXB8z6O8Fvm4da6WJ\nHBhYLN70eFBGT2fvkQIDAQAB\n-----END PUBLIC KEY-----\n",
    encryptedPkcs8Pem: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCs/Lzt8+zpKmadM1Qf\nSqkkAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQeP5SlwKGCHysz1b+\n4WhZZQRAHlazhk9/MX34i/CU1CeB078Lf5Vgmpp20nS0x51xToZzodunSXJ/4DnX\n6njaObGqu7KV7xhHDbcEIIgeHAR8GQ==\n-----END ENCRYPTED PRIVATE KEY-----\n",
    opensshEncrypted: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAw\n68NTp1Caekq20Mhhm0zKAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIF+C\n1Upo0jl56XVoZra5DOJ37zTh1drsOHHFQJ1WNRqNAAAAkCt5x/vqoNzkK/ULvACu\n1qFOtcTIxF5QXaG4xhgfcEFteDtfQeXYAqHfGwEtTWLBIJhNo/6iC9OSvXBqPABe\nYZqnWBontiE1VhQXi//18yy6CnU9xKePLld6S3UshLKjsjMsPhuR9YgrJh48VE6B\nM8+7U6O0n6ATghsAATsdCU0JbithaXqROxvjWj0x6PDbSA==\n-----END OPENSSH PRIVATE KEY-----\n",
    opensshRsaPrivate: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdz\nc2gtcnNhAAAAAwEAAQAAAIEAwLU7S+z2VvWDTK+BPVjZlY2jMeRcmSt2lcCWXYRn\ns3uhBdMbTwqHnf9omxCDzUhNfQgc3NGwo0RkrLTH/PdvQhD0U+OPi+od9kfEgiDo\nf+h3tKlywkIcvIjiniw70JuXqjirhN9Wo/6obbHW1KQcLEuOT6wRgI5CBuCEFNc1\n2Y8AAAH4uAHuPLgB7jwAAAAHc3NoLXJzYQAAAIEAwLU7S+z2VvWDTK+BPVjZlY2j\nMeRcmSt2lcCWXYRns3uhBdMbTwqHnf9omxCDzUhNfQgc3NGwo0RkrLTH/PdvQhD0\nU+OPi+od9kfEgiDof+h3tKlywkIcvIjiniw70JuXqjirhN9Wo/6obbHW1KQcLEuO\nT6wRgI5CBuCEFNc12Y8AAAADAQABAAAAgCa8x5ytl59HXwttRDeGwsZTYHjJBOwt\nVnsn6ZIG6amksmuvUhADd9uE2gxBt5zuadU2akbhR/ap6urktEbfnld52Raau0bn\nEcuKoPspD5QkrXy2Uvq25eXwdonNZVCLYuSxxjcs8+P3m1xoG5t/+KpNIOXUucKu\n81boZyRRt8PRAAAAQQC00SV+dPrKa4L/89RoSR+0oJZc8Xc/s2TjScdHf0xZGxUP\nfbacOzGHLRRRFou6Fuhw8TOSNvwvdG8NQM1z9BjsAAAAQQDydOIBmEN4o8qcW5rW\nHtzZ3/+d8dS8NYDq5bx7hCF8QAOzeEC6BWsfphOdSTK9oH394/SOmLZHtDHLsJhH\n3W4tAAAAQQDLePIZlVAXw7qkwPlw5je/UPxdZZ/zuOPkolKD2KRrzLVkdW8Recdb\nnyF3EwXUNrDzPlVBAHozeJ14qvnNpLgrAAAAAAEC\n-----END OPENSSH PRIVATE KEY-----\n",
    opensshRsaPublic: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC30HemHgHFh82m/CcMkquZFCkDascBbi9o0kp2NVeJSk6h9Hc8tp6lBpCgT4/9glIAHEqP47kmsh9MUn84qb1pwXwsPw/IMhprIRQV/yaIs4s1mA4e34sq2IMgfm1L8n2B+mrAT3JzbZ/k7S1s3Pj5xNV/CmruQQlPSKffuqQ1aQ==",
    opensshEcdsaPublic: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPzTlKxu6KbDrJ4/uUkmwTqYoR70gSVS9GPyaaa0aXCLcPnfuoXT4kQQuiUn/e4clUai50FweejcHRq3kzGxJTY=",
    jwkRsa: "{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}",
    jwkX25519: "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0\"}",
    jwkSet: "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0\"}]}",
};
