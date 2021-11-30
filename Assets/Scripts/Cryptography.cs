using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class Cryptography
{
    public enum EncryptionType { AES, DES, RSA }

    /// <summary>Takes in a key and string to encrypt and encrypts it with a specified encryption type.</summary>
    /// <param name="key">The key to encrypt with.</param>
    /// <param name="textToEncrypt">The string of text to encrypt.</param>
    /// <param name="encryptionType">The type of encryption to perform.</param>
    /// <returns>textToEncrypt, but encrypted with the specified encryption type.</returns>
    public static string Encrypt(string key, string textToEncrypt, EncryptionType encryptionType)
    {
        switch (encryptionType)
        {
            case EncryptionType.AES:
                return EncryptAES(key, textToEncrypt);
            case EncryptionType.DES:
            case EncryptionType.RSA:
            default:
                return "";
        }
    }
    
    /// <summary>Takes in a key and cipher text to decrypt and decrypts it with a specified encryption type.</summary>
    /// <param name="key">The key to encrypt with.</param>
    /// <param name="textToEncrypt">The string of text to encrypt.</param>
    /// <param name="encryptionType">The type of encryption to perform.</param>
    /// <returns>textToEncrypt, but encrypted with the specified encryption type.</returns>
    public static string Decrypt(string key, string cipherText, EncryptionType decryptionType)
    {
        switch (decryptionType)
        {
            case EncryptionType.AES:
                return DecryptAES(key, cipherText);
            case EncryptionType.DES:
            case EncryptionType.RSA:
            default:
                return "";
        }
    }
    
    /// <summary>AES encryption that operates on a key and string.</summary>
    private static string EncryptAES(string key, string textToEncrypt)
    {
        byte[] initVector = new byte[16];
        byte[] array;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = initVector;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream =
                    new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter((Stream) cryptoStream))
                    {
                        streamWriter.Write(textToEncrypt);
                    }

                    array = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(array);
    }

    /// <summary>AES encryption that operates on a key and string.</summary>
    private static string DecryptAES(string key, string cipherText)
    {
        byte[] initVector = new byte[16];
        byte[] buffer = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = initVector;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                using (CryptoStream cryptoStream =
                    new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader((Stream) cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }
}
