using Mirror;
using System;
using UnityEngine;
using UnityEngine.UI;

// ChatBehavior inspired by Dzung Nguyen's tutorial: https://dzungpng.github.io/2020/07/10/mirror/ 
public class ChatBehaviour : NetworkBehaviour {
    [SerializeField] private Text chatText = null;
    [SerializeField] private InputField inputField = null;
    [SerializeField] private GameObject canvas = null;

    const string key = "b14ca5898a4e4133bbce2ea2315a1916";

    private static event Action<string> OnMessage;

    // Called when the a client is connected to the server
    public override void OnStartAuthority() {
        canvas.SetActive(true);

        OnMessage += HandleNewMessage;
    }

    // Called when a client has exited the server
    [ClientCallback]
    private void OnDestroy() {
        if (!hasAuthority) { return; }

        OnMessage -= HandleNewMessage;
    }

    // When a new message is added, update the Scroll View's Text to include the new message
    private void HandleNewMessage(string message)
    {
        chatText.text += message;
    }

    // When a client hits the enter button, send the message in the InputField
    [Client]
    public void Send() {
        if (!Input.GetKeyDown(KeyCode.Return)) { return; }
        if (string.IsNullOrWhiteSpace(inputField.text)) { return; }
        CmdSendMessage(inputField.text);
        inputField.text = string.Empty;
    }

    [Command]
    private void CmdSendMessage(string message) {
        // Validate message
        message = Cryptography.Encrypt(key, $"[{connectionToClient.connectionId}]: {message}", Cryptography.EncryptionType.DES);
        RpcHandleMessage(message);
    }

    [ClientRpc]
    private void RpcHandleMessage(string message) {
        message = Cryptography.Decrypt(key, message, Cryptography.EncryptionType.DES);
        OnMessage?.Invoke($"\n{message}");
    }
}