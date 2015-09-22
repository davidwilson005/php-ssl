<?php

// show all errors
error_reporting(-1);
ini_set('display_errors', 1);

// source public certificate/private key pair, created for testing
// command used:  openssl req -x509 -newkey rsa:2048 -keyout source_private.pem -out source_public.pem -days 3650 -nodes
$sourcePublicKey = openssl_get_publickey(file_get_contents('/var/www/keys/source_public.pem'));
$sourcePrivateKey = openssl_get_privatekey(file_get_contents('/var/www/keys/source_private.pem'));

// destination public certificate/private key pair, created for testing
// command used:  openssl req -x509 -newkey rsa:2048 -keyout dest_private.pem -out dest_public.pem -days 3650 -nodes
$destPublicKey = openssl_get_publickey(file_get_contents('/var/www/keys/dest_public.pem'));
$destPrivateKey = openssl_get_privatekey(file_get_contents('/var/www/keys/dest_private.pem'));

// source user data
$userId = '1234567890';
$groupId = '99';
$email = 'thisisareallyreallylongemail@gmail.com';

// build data message
$message = array(
    'user_id'   => $userId,
    'group_id'  => $groupId,
    'email'     => $email,
);

// package message in JSON format to create hash
$jsonMessage = json_encode($message);

// create hash to verify message
$messageHash = hash('sha256', $jsonMessage);

// encrypt message hash with source private key to create signature
$signature = null;
openssl_private_encrypt($messageHash, $signature, $sourcePrivateKey);

// add message + signature (base64 for json) to message for encryption
$message = json_encode(array(
    'message'   => $message,
    'signature' => base64_encode($signature)
));

// create 256 bit random session key
$sessionKey = openssl_random_pseudo_bytes(32);

// create initialization vector for symmetric encryption
// this is for extra security, guarentees encrypted text is unique
$iv = openssl_random_pseudo_bytes(16);

// encrypt message with session key
// result is base64 encoded by default
$encryptedMessage = openssl_encrypt($message, 'aes256', $sessionKey, 0, $iv);

// encrypt session key with dest public key
$encyrptedSessionKey = null;
openssl_public_encrypt($sessionKey, $encryptedSessionKey, $destPublicKey);

// build message envelope
// convert to base64 for json encoding
$envelope = json_encode(array(
    'session_key'   => base64_encode($encryptedSessionKey),
    'iv'            => base64_encode($iv),
    'message'       => $encryptedMessage
));

// base64 again to put in customer's form
$envelope = base64_encode($envelope);

// post to magento
echo "<form method=\"post\"><input type=\"hidden\" name=\"envelope\" value=\"$envelope\" /><input type=\"submit\" value=\"Send Message\" /></form>";

/*  DESTINATION SIDE */
if (isset($_POST['envelope'])) {

    // base 64 decode data
    $envelope = base64_decode($_POST['envelope']);

    // convert to PHP array
    $envelope = json_decode($envelope, true);

    // decrypt session key with dest private key
    $decryptedSessionKey = null;
    openssl_private_decrypt(base64_decode($envelope['session_key']), $decryptedSessionKey, $destPrivateKey);

    // decrypt message with session key and initialization vector
    $decryptedMessage = openssl_decrypt($envelope['message'], 'aes256', $decryptedSessionKey, 0, base64_decode($envelope['iv']));

    // convert to PHP array
    $message = json_decode($decryptedMessage, true);

    // decrypt signature with source public key to get message hash
    openssl_public_decrypt(base64_decode($message['signature']), $messageHash, $sourcePublicKey);

    // hash json message to verify hash
    $verifyHash = hash('sha256', json_encode($message['message']));

    echo "<p>Signature Verification: ";
    if ($messageHash === $verifyHash) {
        echo "OK";
    } else {
        echo "FAIL";
    }
    echo "</p>";

    // output result
    echo "<p>Result: </p>";
    echo "<pre>".print_r($message, true)."</pre>";
}
?>