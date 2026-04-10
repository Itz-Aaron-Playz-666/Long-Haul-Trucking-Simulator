using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SecureAssetManager
{
    private readonly string constantSha256Key = "YOUR_CONSTANT_SHA256_HASH";
    private readonly string sessionSha512Key;

    public SecureAssetManager()
    {
        // Generate a new SHA-512 session key each run
        using var sha512 = SHA512.Create();
        var randomBytes = Guid.NewGuid().ToByteArray();
        sessionSha512Key = BitConverter.ToString(sha512.ComputeHash(randomBytes))
            .Replace("-", "").ToLowerInvariant();
    }

    public byte[] LoadAsset(string path, byte[] aesKey, byte[] aesIV)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Asset not found.");

        byte[] encryptedData = File.ReadAllBytes(path);

        // Verify SHA-256
        string hash256 = ComputeSHA256(encryptedData);
        if (hash256 != constantSha256Key)
            throw new UnauthorizedAccessException("Asset integrity check failed (SHA-256).");

        // Verify SHA-512 (partial match for dynamic check)
        string hash512 = ComputeSHA512(encryptedData);
        if (!hash512.StartsWith(sessionSha512Key.Substring(0, 16)))
            throw new UnauthorizedAccessException("Asset integrity check failed (SHA-512).");

        // Decrypt asset
        return DecryptAES(encryptedData, aesKey, aesIV);
    }

    private string ComputeSHA256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return BitConverter.ToString(sha256.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
    }

    private string ComputeSHA512(byte[] data)
    {
        using var sha512 = SHA512.Create();
        return BitConverter.ToString(sha512.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
    }

    private byte[] DecryptAES(byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new MemoryStream();
        cs.CopyTo(reader);
        return reader.ToArray();
    }
}
