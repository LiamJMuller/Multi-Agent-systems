N = 5; % number of agents
maxIter = 100; % maximum number of iterations
epsilon = 0.1; % step size

% adjacent matrix based on graph
Adj = zeros(N);
Adj(1,4) = 1; Adj(4,1) = 1; % A-D
Adj(4,3) = 1; Adj(3,4) = 1; % D-C
Adj(3,2) = 1; Adj(2,3) = 1; % C-B
Adj(3,5) = 1; Adj(5,3) = 1; % C-E
Adj(2,5) = 1; Adj(5,2) = 1; % B-E

% number of neighbours per agent
deg = diag(sum(Adj, 2));

% Laplacian matrix L = D-A
L = deg-Adj;

% initialising random initial values for 3 parameters
params = {'Brightness', 'Contrast', 'Sharpness'};
initialValues = rand(N, 3)*100; % random values between 0 and 100
states = zeros(N, maxIter+1, 3);
states(:,1,:) = initialValues;

% run consensus for each parameter independently
for p =1:3 % loop over parameters
    for k = 1:maxIter
        states(:,k+1,p) = states(:,k,p) - epsilon * L * states(:,k,p);
    end
end

% plotting convergence for each parameter
figure;
for p = 1:3
    subplot(3,1,p);
    plot(0:maxIter, squeeze(states(:, :, p)));
    title(['Concensus on ', params{p}]);
    xlabel('Iteration'); ylabel('Value');
    legend('Agent A', 'B', 'C', 'D', 'E');
    grid on;
end

% final consensus values
final = squeeze(states(:, end, :));
disp('Final Concensus Values:');
disp(['Brightness: ' num2str(mean(final(:,1)))]);
disp(['Contrast: ' num2str(mean(final(:,2)))]);
disp(['Sharpness: ' num2str(mean(final(:,3)))]);

% 2.4 security protocol

agentNames = {'A', 'B', 'C', 'D', 'E'};
secureAgent = cell(1, N);
for i = 1:N
    secureAgent{i} = SecureAgent(agentName{i});
end

% exchanging public keys
for i = 1:N
    for j = i+1:N
        if Adj(i,j) ==1
            secureAgents{i}.sharePublicKey(secureAgent{j});
        end
    end
end

% demo-ing secure image transmission between agents A and D
senderIdx = 1; % Agent A
receiverIdx = 4; % Agent D
testImage = randi([0, 255], 100, 100); % random grayscale image

fprintf('Transmitting secure image from Agent %s to Agent %s\n', ... 
        agentNames{senderIdx}, agentNames{receiverIdx});

% decrypting and verifying
[receivedImg, isValid] = secureAgent{receiverIdx}.receiveSecureImg(packet, agentNames{senderIdx});

if isValid && isequal(testImage, receivedImg)
    fprintf('Image is transmitted securely and verified successfully.\n');
else
    fprintf('Image verification failed or image is corrupted.\n');
end

% mutual auth
fprintf('Performing mutal authrntication between Agent %s and Agent %s\n', ...
        agentNames{senderIdx}, agentNames{receiverIdx});
authSuccess = secureAgent{senderIdx}.authenticate(secureAgent{receiverIdx});
if authSuccess
    fprintf('Mutual authentication successful');
else
    fprintf('Authentication failed');
end

% section 2.5
% tasks: noise reduction, edge detection, feature extraction, color correlation, compression
% Tasks: Noise Reduction, Edge Detection, Feature Extraction, Color Correction, Compression
tasks = {'Noise Reduction', 'Edge Detection', 'Feature Extraction', 'Color Correction', 'Compression'};

% Random capabilities (bids): Higher value = better capability
capabilities = rand(5,5);  % Rows: agents, Columns: tasks

% Coordinator: Agent 3 (C)
coordinator = 3;

% Simulate bidding: Only neighbors can bid
allocation = zeros(1,5);  % Task to agent
for t = 1:5
    % Announce to neighbors
    neighbors = find(Adj(coordinator,:));
    bidders = [coordinator, neighbors];  % Include self if capable
    bids = capabilities(bidders, t);
    [~, winnerIdx] = max(bids);
    allocation(t) = bidders(winnerIdx);
end

% Display allocation
for t = 1:5
    agentLabel = char('A' + allocation(t) - 1);
    disp([tasks{t} ' allocated to Agent ' agentLabel]);
end

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
            % Hash image
            md = java.security.MessageDigest.getInstance('SHA-256');
            md.update(uint8(image(:)));
            hash = typecast(md.digest(), 'uint8')';
            
            % Sign hash
            signer = java.security.Signature.getInstance('SHA256withRSA');
            signer.initSign(obj.privateKey);
            signer.update(hash);
            signature = typecast(signer.sign(), 'uint8')';
            
            % Package data
            data = struct('image', image, 'sig', signature, 'sender', obj.agentID);
            bytes = getByteStreamFromArray(data);
            
            % Encrypt with receiver's public key
            cipher = javax.crypto.Cipher.getInstance('RSA/ECB/PKCS1Padding');
            cipher.init(1, obj.peerPublicKeys(receiverID));
            packet = typecast(cipher.doFinal(bytes), 'uint8')';
        end
        
        function [image, valid] = receiveSecureImage(obj, packet, senderID)
            % Decrypt with private key
            cipher = javax.crypto.Cipher.getInstance('RSA/ECB/PKCS1Padding');
            cipher.init(2, obj.privateKey);
            bytes = cipher.doFinal(packet);
            data = getArrayFromByteStream(bytes);
            
            % Verify signature
            md = java.security.MessageDigest.getInstance('SHA-256');
            md.update(uint8(data.image(:)));
            hash = typecast(md.digest(), 'uint8')';
            
            verifier = java.security.Signature.getInstance('SHA256withRSA');
            verifier.initVerify(obj.peerPublicKeys(senderID));
            verifier.update(hash);
            valid = verifier.verify(data.sig);
            
            image = data.image;
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