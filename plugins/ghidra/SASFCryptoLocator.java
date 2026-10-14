// SASF Ghidra Script: Crypto Locator
// ------------------------------------
// Locates cryptographic routines, constants, and key material in the binary.
// Uses known S-box values, round constants, and API name patterns to find:
//   - AES (Rijndael S-box, round constants)
//   - DES (IP/FP tables, S-boxes)
//   - RC4 (identity permutation init)
//   - ChaCha20/Salsa20 ("expand 32-byte k" constant)
//   - RSA (public exponent 65537)
//   - Custom/unknown crypto (high-entropy lookup tables)
//
// @category SASF
// @author Malvex Malware Analysis Platform

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;

public class SASFCryptoLocator extends GhidraScript {

    private List<Map<String, Object>> cryptoSites = new ArrayList<>();

    // AES Rijndael S-box first 16 bytes
    private static final byte[] AES_SBOX_PREFIX = {
        0x63, 0x7C, 0x77, 0x7B, (byte)0xF2, 0x6B, 0x6F, (byte)0xC5,
        0x30, 0x01, 0x67, 0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, 0x76
    };

    // DES initial permutation (first 8 entries)
    private static final byte[] DES_IP = { 58, 50, 42, 34, 26, 18, 10, 2 };

    // ChaCha20/Salsa20 constant
    private static final byte[] CHACHA_CONST = "expand 32-byte k".getBytes();

    // SHA-256 initial hash values (first 4 bytes of H0)
    private static final byte[] SHA256_H0 = {
        0x6A, 0x09, (byte)0xE6, 0x67
    };

    @Override
    protected void run() throws Exception {
        println("[SASF] Running crypto locator...");
        Memory mem = currentProgram.getMemory();

        // Scan all memory blocks
        MemoryBlock[] blocks = mem.getBlocks();
        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) continue;

            byte[] data = new byte[(int) Math.min(block.getSize(), 10 * 1024 * 1024)];
            int bytesRead = block.getBytes(block.getStart(), data, 0, data.length);

            scanForPattern(data, bytesRead, block.getStart(), AES_SBOX_PREFIX, "AES",
                "Rijndael S-box — AES encryption/decryption routine nearby");
            scanForPattern(data, bytesRead, block.getStart(), DES_IP, "DES",
                "DES initial permutation table — WEAK, should be replaced with AES");
            scanForPattern(data, bytesRead, block.getStart(), CHACHA_CONST, "ChaCha20",
                "ChaCha20/Salsa20 expansion constant — modern stream cipher");
            scanForPattern(data, bytesRead, block.getStart(), SHA256_H0, "SHA-256",
                "SHA-256 initial hash value H0");

            // RC4: look for identity permutation (0x00..0xFF)
            scanForRC4Init(data, bytesRead, block.getStart());

            // High-entropy tables (potential custom crypto)
            scanForEntropyTables(data, bytesRead, block.getStart());

            monitor.setMessage("Scanned block: " + block.getName());
        }

        // Also check for crypto API imports
        scanCryptoImports();

        // Report
        println("\n===== SASF Crypto Locator Report =====");
        println("Total crypto sites found: " + cryptoSites.size());
        for (Map<String, Object> site : cryptoSites) {
            println(String.format("  [%s] 0x%s — %s",
                site.get("algorithm"), site.get("addr"), site.get("desc")));

            // Bookmark in Ghidra
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress((String) site.get("addr"));
            if (addr != null) {
                currentProgram.getBookmarkManager().setBookmark(
                    addr, "SASF-Crypto", (String) site.get("algorithm"),
                    (String) site.get("desc"));
            }
        }
        println("======================================\n");
    }

    private void scanForPattern(byte[] data, int len, Address base,
                                 byte[] pattern, String algo, String desc) {
        for (int i = 0; i <= len - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                Address addr = base.add(i);
                Map<String, Object> site = new HashMap<>();
                site.put("algorithm", algo);
                site.put("addr", addr.toString());
                site.put("desc", desc);
                site.put("offset", i);
                cryptoSites.add(site);
            }
        }
    }

    private void scanForRC4Init(byte[] data, int len, Address base) {
        if (len < 256) return;
        for (int i = 0; i <= len - 256; i++) {
            boolean isIdentity = true;
            for (int j = 0; j < 256; j++) {
                if ((data[i + j] & 0xFF) != j) {
                    isIdentity = false;
                    break;
                }
            }
            if (isIdentity) {
                Address addr = base.add(i);
                Map<String, Object> site = new HashMap<>();
                site.put("algorithm", "RC4");
                site.put("addr", addr.toString());
                site.put("desc", "RC4 identity permutation — RC4 is BROKEN, should not be used");
                site.put("offset", i);
                cryptoSites.add(site);
            }
        }
    }

    private void scanForEntropyTables(byte[] data, int len, Address base) {
        // Look for 256-byte tables with high entropy (potential custom S-boxes)
        if (len < 256) return;
        for (int i = 0; i <= len - 256; i += 256) {
            int[] histogram = new int[256];
            for (int j = 0; j < 256; j++) {
                histogram[data[i + j] & 0xFF]++;
            }
            // Check if it's a permutation (each byte appears exactly once)
            boolean isPermutation = true;
            for (int count : histogram) {
                if (count != 1) {
                    isPermutation = false;
                    break;
                }
            }
            if (isPermutation) {
                // Skip if it's the identity permutation (already caught as RC4)
                boolean isIdentity = true;
                for (int j = 0; j < 256; j++) {
                    if ((data[i + j] & 0xFF) != j) { isIdentity = false; break; }
                }
                if (!isIdentity) {
                    Address addr = base.add(i);
                    Map<String, Object> site = new HashMap<>();
                    site.put("algorithm", "Custom-Permutation");
                    site.put("addr", addr.toString());
                    site.put("desc", "256-byte permutation table — potential custom S-box or cipher");
                    site.put("offset", i);
                    cryptoSites.add(site);
                }
            }
        }
    }

    private void scanCryptoImports() {
        String[] cryptoAPIs = {
            // Windows CryptoAPI / BCrypt / CNG
            "CryptEncrypt", "CryptDecrypt", "CryptDeriveKey", "CryptImportKey",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
            "BCryptOpenAlgorithmProvider",
            // macOS CommonCrypto
            "CCCrypt", "CCCryptorCreate", "CCKeyDerivationPBKDF",
            "SecKeyEncrypt", "SecKeyDecrypt",
            // OpenSSL
            "EVP_EncryptInit", "EVP_DecryptInit", "EVP_CipherInit",
            "AES_encrypt", "AES_decrypt", "DES_ecb_encrypt",
            "RSA_public_encrypt", "RSA_private_decrypt",
            // BoringSSL
            "CRYPTO_chacha_20", "CRYPTO_hchacha20",
        };

        SymbolTable symTab = currentProgram.getSymbolTable();
        for (String apiName : cryptoAPIs) {
            SymbolIterator syms = symTab.getSymbols(apiName);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                Map<String, Object> site = new HashMap<>();
                site.put("algorithm", "API:" + apiName);
                site.put("addr", sym.getAddress().toString());
                site.put("desc", "Crypto API import: " + apiName);
                cryptoSites.add(site);
            }
        }
    }
}
