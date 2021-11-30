using UnityEngine;

public class CryptoTests : MonoBehaviour
{
    private void Start()
    {
        string key = "b14ca5898a4e4133bbce2ea2315a1916";

        string inputString = "My name is minion bob!";
        string cipher = Cryptography.Encrypt(key, inputString, Cryptography.EncryptionType.AES);
        string decrypted = Cryptography.Decrypt(key, cipher, Cryptography.EncryptionType.AES);
        
        print($"Input string: {inputString}");
        print($"Cipher text: {cipher}");
        print($"Decrypted: {decrypted}");
    }
}
