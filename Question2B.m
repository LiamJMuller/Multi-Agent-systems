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
tasks = {'Noise Reduction', 'Edge Detection', 'Feature Extraction', 'Color Correlation', 'Compression'};

% random capabilities, higher value = better capability
capabilities = rand(5,5);

% choosing agent 3 as coordinator
coordinator = 3;

% simulate bidding, limiting it to neighbours
allocation = zeros(1,5);
for t = 1:5
    % announce to neighbours
    neighbours = find(Adj(coordinator, :));
    bidders = [coordinator, neighbours];
    bids = capabilities(bidders, t);
    [~, winnerIdx] = max(bids);
    allocations(t) = bidders(winnerIdx);
end

% display allocation
for t=1:5
    agentLabel=char('A' + allocations(t)-1);
    disp([tasks{t} ' allocated to Agent ' agentLabel]);
end

% the secure agent class definition
classdef SecureAgent < handle
    properties
        agentID
        privateKey
        sharePublicKey
        peerPublicKeys
    end

    methods
        function obj = SecureAgent(agentID)
            obj.agentID = agentID;
            obj.peerPublicKeys = containers.Map();
            % geneerating RSA key pair
            kpg = java.security.KeyPairGenerator.getInstance('RSA');
            kpg.initialize(2048);
            keys = kpg.generateKeyPair();
            obj.publicKey=keys.getPublic();
            obj.privateKey=keys.getPrivate();
        end

        function sharePublicKey = sendSecureImage(obj, peer)
            obj.peerPublicKeys(peer.agentID)=peer.publicKey;
            peer.peerPublicKeys(obj.agentID)=obj.publicKey;
        end

        function packet = sendSecureImage(obj, image, receiverID)
            % hashmapping the image
            md = java.security.MessageDigest.getInstance('SHA-256');
            md.update(uint8(image(:)));
            hash = typecast(md.digest(), 'uint8')';

            % sign the hash
            singer = java.security.Signature.getInstance('SHA256withRSA');
            singer.initSign(obj.privateKey);
            singer.update(hash);
            signature = typecast(singer.sign(), 'uint8');

            % package data
            data = struct('Image', image, 'sig', signature, 'sender', obj.agentID);
            bytes = getByteStreamFromArray(data);

            % encrypt with receiver's public key
            cipher = javax.crypto.Cipher.getInstance('RSA/ECB/PKCS1Padding');
            cipher.init(1, obj.peerPublicKeys(receiverID));
            packet = typecast(cipher.doFinal(bytes), 'uint8');
        end

        function[image, valid] = receiveSecureImg(obj, packet, senderID)
            % decrypting with a new private key
            cipher = javax.crypto.Cipher.getInstance('RSA/ECB/PKCS1Padding');
            cipher.init(2, obj.privateKey);
            bytes = cipher.doFinal(packet);
            data = getArrayFromByteStream(bytes);

            % verify the signature
            md = java.security.MessageDigest.getInstance