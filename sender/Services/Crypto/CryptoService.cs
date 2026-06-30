/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using System.Security.Cryptography;
using System.Text;
using Sender.Logger;
using Sender.Queue;

namespace Sender.Crypto;

public class CryptoService(AppLogger appLogger, IKeyProvider keyProvider)
{
    public PasswordChangeEvent DecryptPassword(PasswordChangeEvent changeEvent)
    {
        var fileName = Path.GetFileName(changeEvent.FilePath);
        try
        {
            var keyVersion = ExtractKeyVersion(changeEvent.FilePath!);
            var rawKey = keyProvider.GetKey(keyVersion);
            if (rawKey is null)
            {
                appLogger.ToFile($"Key {keyVersion} not found", LogLevel.Error);
                throw new InvalidDataException($"Key {keyVersion} not found");
            }

            var blob = Convert.FromBase64String(changeEvent.Password);
            var decryptedPassword = DecryptBlob(rawKey, blob);

            return changeEvent with { Password = decryptedPassword };
        }
        catch (Exception ex)
        {
            appLogger.ToAll($"Failed to decrypt password from {fileName}: {ex.Message}", LogLevel.Error);
            throw;
        }
    }

    public PasswordChangeEvent EncryptPassword(PasswordChangeEvent changeEvent, string? keyVersion = null)
    {
        try
        {
            var usedKeyVersion = keyVersion ?? keyProvider.GetLatestKeyVersion() ?? throw new InvalidDataException("No latest key version found");
            var rawKey = keyProvider.GetKey(usedKeyVersion)
                ?? throw new InvalidDataException($"Key {usedKeyVersion} not found");

            var blob = EncryptToBlob(rawKey, changeEvent.Password);
            var encryptedPassword = Convert.ToBase64String(blob);

            return changeEvent with { Password = encryptedPassword };
        }
        catch (Exception ex)
        {
            appLogger.ToAll($"Failed to encrypt password: {ex.Message}", LogLevel.Error);
            throw;
        }
    }

    public static string ExtractKeyVersion(string filePath) => Path
        .GetFileNameWithoutExtension(filePath)
        .Split('_')
        .Last();

    public static string DecryptBlob(byte[] key, byte[] blob)
    {
        if (blob.Length <= Constants.Crypto.NonceSize + Constants.Crypto.TagSize)
            throw new InvalidDataException("Event file blob is too small to contain nonce, tag and ciphertext");

        var nonce = blob[..Constants.Crypto.NonceSize];
        var tag = blob[Constants.Crypto.NonceSize..(Constants.Crypto.NonceSize + Constants.Crypto.TagSize)];
        var ciphertext = blob[(Constants.Crypto.NonceSize + Constants.Crypto.TagSize)..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, Constants.Crypto.TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }

    public string EncryptPasswordToBase64(string password, string keyVersion)
    {
        var rawKey = keyProvider.GetKey(keyVersion)
            ?? throw new InvalidOperationException($"Key '{keyVersion}' not found in registry");
        return Convert.ToBase64String(EncryptToBlob(rawKey, password));
    }

    public string DecryptPasswordFromBase64(string encryptedBase64, string keyVersion)
    {
        var rawKey = keyProvider.GetKey(keyVersion)
            ?? throw new InvalidOperationException($"Key '{keyVersion}' not found in registry");
        var blob = Convert.FromBase64String(encryptedBase64);
        return DecryptBlob(rawKey, blob);
    }

    public static byte[] EncryptToBlob(byte[] key, string plaintext)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = new byte[Constants.Crypto.NonceSize];
        var tag = new byte[Constants.Crypto.TagSize];
        var ciphertext = new byte[plaintextBytes.Length];

        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key, Constants.Crypto.TagSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        return
        [
            ..nonce,
            ..tag,
            ..ciphertext
        ];
    }
}
