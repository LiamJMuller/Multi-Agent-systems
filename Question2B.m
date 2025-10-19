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
    title(['Consensus on ', params{p}]);
    xlabel('Iteration'); ylabel('Value');
    legend('Agent A', 'B', 'C', 'D', 'E');
    grid on;
end

% final consensus values
final = squeeze(states(:, end, :));
disp('Final Consensus Values:');
disp(['Brightness: ' num2str(mean(final(:,1)))]);
disp(['Contrast: ' num2str(mean(final(:,2)))]);
disp(['Sharpness: ' num2str(mean(final(:,3)))]);

% 2.4 security protocol
agentNames = {'A', 'B', 'C', 'D', 'E'};
secureAgent = cell(1, N);
for i = 1:N
    secureAgent{i} = SecureAgent(agentNames{i}); % Fixed to agentNames
end

% exchanging public keys
for i = 1:N
    for j = i+1:N
        if Adj(i,j) ==1
            secureAgent{i}.sharePublicKey(secureAgent{j});
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
packet = secureAgent{senderIdx}.sendSecureImage(testImage, agentNames{receiverIdx});
[receivedImg, isValid] = secureAgent{receiverIdx}.receiveSecureImage(packet, agentNames{senderIdx});

if isValid && isequal(testImage, receivedImg)
    fprintf('Image is transmitted securely and verified successfully.\n');
else
    fprintf('Image verification failed or image is corrupted.\n');
end

% mutual auth
fprintf('Performing mutual authentication between Agent %s and Agent %s\n', ...
        agentNames{senderIdx}, agentNames{receiverIdx});
authSuccess = secureAgent{senderIdx}.authenticate(secureAgent{receiverIdx});
if authSuccess
    fprintf('Mutual authentication successful\n');
else
    fprintf('Authentication failed\n');
end

% section 2.5
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

% temporary serialization functions
function bytes = getByteStreamFromArray(data)
    % convert struct to byte stream using a temporary file
    tempFile = tempname;
    save(tempFile, '-struct', 'data', '-v7.3'); % saving as MAT file
    fid = fopen(tempFile, 'r');
    bytes = fread(fid, inf, 'uint8');
    fclose(fid);
    delete(tempFile);
end
function data = getArrayFromByteStream(bytes)
    % convert byte stream back to struct
    tempFile = tempname;
    fid = fopen(tempFile, 'w');
    fwrite(fid, bytes, 'uint8');
    fclose(fid);
    data = load(tempFile, '-mat');
    delete(tempFile);
    data = data.data; % extract struct from loaded data
end

% adding SecureAgent.m for secure communication
% addpath('SecureAgent.m');