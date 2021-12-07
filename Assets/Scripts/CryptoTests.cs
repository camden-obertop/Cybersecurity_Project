using UnityEngine;

public class CryptoTests : MonoBehaviour
{
    private void Start()
    {
        string key = "b14ca5898a4e4133bbce2ea2315a1916";

        string inputString = "!";
        string cipher = Cryptography.Encrypt(inputString, Cryptography.EncryptionType.AES, key);
        string decrypted = Cryptography.Decrypt(cipher, Cryptography.EncryptionType.AES, key);
        
        print($"Input string: {inputString}");
        print($"Cipher text: {cipher}");
        print($"Decrypted: {decrypted}");
    }
}
