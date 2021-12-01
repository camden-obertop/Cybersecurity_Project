using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class Cryptography
{
    private static string aes_iv = "jdxnWolsAyO7kCfWuyr13g==";

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
                return EncryptDES(key, textToEncrypt);
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
                return DecryptDES(key, cipherText);
            case EncryptionType.RSA:
            default:
                return "";
        }
    }
    
    /// <summary>AES encryption that operates on a key and string.</summary>
    private static string EncryptAES(string key, string textToEncrypt)
    {
        byte[] initVector = Convert.FromBase64String(aes_iv);
        byte[] array;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = initVector;
            aes.Mode = CipherMode.CBC;
            
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
        byte[] initVector = Convert.FromBase64String(aes_iv);
        byte[] buffer = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.GenerateIV();
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = initVector;
            aes.Mode = CipherMode.CBC;

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

    private static string EncryptDES(string key, string textToEncrypt)
    {
        TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
        MD5CryptoServiceProvider MD5Provider = new MD5CryptoServiceProvider();
        
        des.Key = MD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
        des.Mode = CipherMode.ECB;

        byte[] buffer = Encoding.UTF8.GetBytes(textToEncrypt);

        return Convert.ToBase64String(des.CreateEncryptor().TransformFinalBlock(buffer, 0, buffer.Length));
    }

    private static string DecryptDES(string key, string textToEncrypt)
    {
        TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
        MD5CryptoServiceProvider HD5Provider = new MD5CryptoServiceProvider();
 
        des.Key = HD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
        des.Mode = CipherMode.ECB;

        byte[] buffer = Convert.FromBase64String(textToEncrypt);
 
        string plaintext = Encoding.UTF8.GetString(des.CreateDecryptor().TransformFinalBlock(buffer, 0, buffer.Length));
        return plaintext;
    }
}
