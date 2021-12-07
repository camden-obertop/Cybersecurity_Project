using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;

public static class Cryptography
{
    private static string aes_iv = "jdxnWolsAyO7kCfWuyr13g==";

    public enum EncryptionType { AES, DES, RSA }

    /// <summary>Takes in a key and string to encrypt and encrypts it with a specified encryption type.</summary>
    /// <param name="key">The key to encrypt with.</param>
    /// <param name="textToEncrypt">The string of text to encrypt.</param>
    /// <param name="encryptionType">The type of encryption to perform.</param>
    /// <returns>textToEncrypt, but encrypted with the specified encryption type.</returns>
    public static string Encrypt(string textToEncrypt, EncryptionType encryptionType, string key=null, RSACryptoServiceProvider provider=null)
    {
        if (string.IsNullOrWhiteSpace(key) && provider == null)
        {
            Debug.LogError("Must provide key or RSACryptoServiceProvider to encrypt text!");
            return null;
        }
        
        switch (encryptionType)
        {
            case EncryptionType.AES:
                return EncryptAES(key, textToEncrypt);
            case EncryptionType.DES:
                return EncryptDES(key, textToEncrypt);
            case EncryptionType.RSA:
                return EncryptRSA(provider, textToEncrypt);
            default:
                return null;
        }
    }
    
    /// <summary>Takes in a key and cipher text to decrypt and decrypts it with a specified encryption type.</summary>
    /// <param name="key">The key to encrypt with.</param>
    /// <param name="textToEncrypt">The string of text to encrypt.</param>
    /// <param name="encryptionType">The type of encryption to perform.</param>
    /// <returns>textToEncrypt, but encrypted with the specified encryption type.</returns>
    public static string Decrypt(string cipherText, EncryptionType decryptionType, string key=null, RSACryptoServiceProvider provider=null)
    {
        if (string.IsNullOrWhiteSpace(key) && provider == null)
        {
            Debug.LogError("Must provide key or RSACryptoServiceProvider to decrypt text!");
            return null;
        }
        
        switch (decryptionType)
        {
            case EncryptionType.AES:
                return DecryptAES(key, cipherText);
            case EncryptionType.DES:
                return DecryptDES(key, cipherText);
            case EncryptionType.RSA:
                return DecryptRSA(provider, cipherText);
            default:
                return null;
        }
    }
    
    /// <summary>Creates and returns a new RSACryptoServiceProvider, used in RSA algorithms.</summary>
    public static RSACryptoServiceProvider GenerateRSAProvider()
    {
        return new RSACryptoServiceProvider();
    }
    
    /// <summary>256-bit AES encryption with CBC cipher and 16 byte IV that operates on a key and string.</summary>
    private static string EncryptAES(string key, string textToEncrypt)
    {
        byte[] initVector = Convert.FromBase64String(aes_iv);

        using Aes aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = initVector;
        aes.Mode = CipherMode.CBC;
            
        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using MemoryStream memoryStream = new MemoryStream();
        using CryptoStream cryptoStream =
            new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
        using (StreamWriter streamWriter = new StreamWriter((Stream) cryptoStream))
        {
            streamWriter.Write(textToEncrypt);
        }

        return Convert.ToBase64String(memoryStream.ToArray());
    }
    
    /// <summary>256-bit AES encryption with CBC cipher and 16 byte IV that operates on a key and string.</summary>
    private static string DecryptAES(string key, string cipherText)
    {
        byte[] initVector = Convert.FromBase64String(aes_iv);
        byte[] buffer = Convert.FromBase64String(cipherText);

        using Aes aes = Aes.Create();
        aes.GenerateIV();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = initVector;
        aes.Mode = CipherMode.CBC;

        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using MemoryStream memoryStream = new MemoryStream(buffer);
        using CryptoStream cryptoStream =
            new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        using StreamReader streamReader = new StreamReader(cryptoStream);
        return streamReader.ReadToEnd();
    }

    /// <summary>64-bit DES encryption with ECB cipher that operates on a key and string.</summary>
    private static string EncryptDES(string key, string textToEncrypt)
    {
        TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
        MD5CryptoServiceProvider MD5Provider = new MD5CryptoServiceProvider();
        
        des.Key = MD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
        des.Mode = CipherMode.ECB;

        byte[] buffer = Encoding.UTF8.GetBytes(textToEncrypt);

        return Convert.ToBase64String(des.CreateEncryptor().TransformFinalBlock(buffer, 0, buffer.Length));
    }

    /// <summary>64-bit DES encryption with ECB cipher that operates on a key and string.</summary>
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

    /// <summary>1024-bit RSA encryption that operates with an RSACryptoServiceProvider and string.</summary>
    private static string EncryptRSA(RSACryptoServiceProvider provider, string textToEncrypt)
    {
        try  
        {
            using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(provider.ExportParameters(false));
            byte[] text = Encoding.UTF8.GetBytes(textToEncrypt);
            byte[] encryptedBytes = rsa.Encrypt(text, false);
            string final = Encoding.UTF8.GetString(encryptedBytes);
            return final;  
        }  
        catch (CryptographicException e)  
        {  
            Debug.LogError($"Error encrypting with RSA! {e.Message}");  
            return null;  
        }
    }
    
    /// <summary>1024-bit RSA decryption that operates with an RSACryptoServiceProvider and string.</summary>
    private static string DecryptRSA(RSACryptoServiceProvider provider, string textToDecrypt)
    {
        try  
        {
            using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(provider.ExportParameters(true));  
            return Encoding.UTF8.GetString(rsa.Decrypt(Encoding.UTF8.GetBytes(textToDecrypt), false));  
        }  
        catch (CryptographicException e)  
        {  
            Debug.LogError($"Error decrypting with RSA! {e.Message}");  
            return null;  
        }          
    }
}
