%% SecureAgent Class Definition
classdef SecureAgent < handle
    properties
        agentID
        privateKey
        publicKey
        peerPublicKeys
    end
    
    methods
        function obj = SecureAgent(agentID)
            obj.agentID = agentID;
            obj.peerPublicKeys = containers.Map();
            % Generate RSA key pair
            kpg = java.security.KeyPairGenerator.getInstance('RSA');
            kpg.initialize(2048);
            keys = kpg.generateKeyPair();
            obj.publicKey = keys.getPublic();
            obj.privateKey = keys.getPrivate();
        end
        
        function sharePublicKey(obj, peer)
            obj.peerPublicKeys(peer.agentID) = peer.publicKey;
            peer.peerPublicKeys(obj.agentID) = obj.publicKey;
        end
        
        function packet = sendSecureImage(obj, image, receiverID)
            % generating a random AES key (16 bytes for AES-128)
            keygen = javax.crypto.KeyGenerator.getInstance('AES');
            keygen.init(128);
            aesKey = keygen.generateKey();
            
            % initialising AES cipher in a CBC mode with PKCS5 padding
            cipher = javax.crypto.Cipher.getInstance('AES/CBC/PKCS5Padding');
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey);

            % Encrypting the image
            iv = cipher.getIV();
            encryptedImage = cipher.doFinal(uint8(image(:)));

            % encrypt the AES key with RSA
            rsaCipher = javax.crypto.Cipher.getInstance('RSA/ECB/PKCS1Padding');
            rsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, obj.peerPublicKeys(receiverID));
            encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

            % Package data
            [rows, cols] = size(image); % capturing the original image size
            data = struct('encryptedImage', typecast(encryptedImage, 'uint8'), ...
                          'encryptedAESKey', typecast(encryptedAESKey, 'uint8'), ...
                          'iv', typecast(iv, 'uint8'), ...
                          'sender', obj.agentID, ...
                          'imageSize', [rows, cols]); % adding image size
            bytes = getByteStreamFromArray(data);
            
            % return packet
            packet = bytes;
        end
        
        function [image, valid] = receiveSecureImage(obj, packet, senderID)
            % deserialise packet
            data = getArrayFromByteStream(packet);

            % decrypt the AES key with RSA
            rsaCipher = javax.crypto.Cipher.getInstance('RSA/ECB/PKCS1Padding');
            rsaCipher.init(javax.crypto.Cipher.DECRYPT_MODE, obj.privateKey);
            aesKeyBytes = rsaCipher.doFinal(data.encryptedAESKey);
            aesKeySpec = javax.crypto.spec.SecretKeySpec(aesKeyBytes, 'AES');
            
            % decrypt the image with AES
            cipher = javax.crypto.Cipher.getInstance('AES/CBC/PKCS5Padding');
            ivSpec = javax.crypto.spec.IvParameterSpec(data.iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, aesKeySpec, ivSpec);
            decryptedBytes = cipher.doFinal(data.encryptedImage);

            % reconstruct image
            image = reshape(typecast(decryptedBytes, 'uint8'), data.imageSize); 

            % verify
            valid = isequal(data.sender, senderID) && ~isempty(image);
        end
        
        function success = authenticate(obj, peer)
            % Challenge-response authentication
            nonce = randi([1e9, 1e10]);
            challenge = typecast(int32(nonce), 'uint8');
            
            % Peer signs nonce
            signer = java.security.Signature.getInstance('SHA256withRSA');
            signer.initSign(peer.privateKey);
            signer.update(challenge);
            response = signer.sign();
            
            % Verify signature
            verifier = java.security.Signature.getInstance('SHA256withRSA');
            verifier.initVerify(peer.publicKey);
            verifier.update(challenge);
            success = verifier.verify(response);
        end
    end
end