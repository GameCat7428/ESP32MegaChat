Perfect! I'll create a complete ESP32 Arduino sketch for your project with all the features you requested. This will be a comprehensive single-file solution.
Action: file_editor create /app/ESP32_ChatServer.ino --file-text "#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <AsyncWebSocket.h>
#include <SD.h>
#include <SPI.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <time.h>

// Pin Configuration
#define BUTTON_PIN 2
#define CS_PIN 15
#define MOSI_PIN 23
#define MISO_PIN 19
#define SCK_PIN 18

// Network Configuration
const char* ap_ssid = \"ESP32_ChatServer\";
const char* ap_password = \"12345678\";

// Server objects
AsyncWebServer server(80);
AsyncWebSocket ws(\"/ws\");

// Global variables
struct User {
  String username;
  String password;
  bool isOnline;
  bool isBanned;
  String avatar;
  String banReason;
  unsigned long lastActivity;
};

struct ChatMessage {
  String username;
  String message;
  String timestamp;
  String attachment;
};

std::vector<User> users;
std::vector<ChatMessage> chatHistory;
std::vector<String> blogPosts;
std::vector<String> supportRequests;
std::map<uint32_t, String> connectedClients; // WebSocket ID to username mapping

// Security variables
std::map<String, unsigned long> lastRequestTime;
std::map<String, int> requestCount;
const int MAX_REQUESTS_PER_MINUTE = 60;
const unsigned long RATE_LIMIT_WINDOW = 60000; // 1 minute

// Utility Functions
String hashPassword(String password) {
  unsigned char hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)password.c_str(), password.length());
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  
  String hashString = \"\";
  for(int i = 0; i < 32; i++) {
    hashString += String(hash[i], HEX);
  }
  return hashString;
}

String getCurrentTimestamp() {
  time_t now;
  struct tm timeinfo;
  time(&now);
  localtime_r(&now, &timeinfo);
  
  char timeString[64];
  strftime(timeString, sizeof(timeString), \"%Y-%m-%d %H:%M:%S\", &timeinfo);
  return String(timeString);
}

bool rateLimitCheck(String clientIP) {
  unsigned long currentTime = millis();
  
  if (lastRequestTime.find(clientIP) == lastRequestTime.end()) {
    lastRequestTime[clientIP] = currentTime;
    requestCount[clientIP] = 1;
    return true;
  }
  
  if (currentTime - lastRequestTime[clientIP] > RATE_LIMIT_WINDOW) {
    lastRequestTime[clientIP] = currentTime;
    requestCount[clientIP] = 1;
    return true;
  }
  
  requestCount[clientIP]++;
  return requestCount[clientIP] <= MAX_REQUESTS_PER_MINUTE;
}

String sanitizeInput(String input) {
  input.replace(\"<\", \"&lt;\");
  input.replace(\">\", \"&gt;\");
  input.replace(\"\\"\", \"&quot;\");
  input.replace(\"'\", \"&#x27;\");
  input.replace(\"/\", \"&#x2F;\");
  return input;
}

// File System Functions
void initSD() {
  SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, CS_PIN);
  
  if (!SD.begin(CS_PIN)) {
    Serial.println(\"SD Card initialization failed!\");
    return;
  }
  
  Serial.println(\"SD Card initialized successfully\");
  
  // Create directory structure
  if (!SD.exists(\"/users\")) SD.mkdir(\"/users\");
  if (!SD.exists(\"/avatars\")) SD.mkdir(\"/avatars\");
  if (!SD.exists(\"/chat\")) SD.mkdir(\"/chat\");
  if (!SD.exists(\"/logs\")) SD.mkdir(\"/logs\");
  if (!SD.exists(\"/config\")) SD.mkdir(\"/config\");
  if (!SD.exists(\"/uploads\")) SD.mkdir(\"/uploads\");
  
  // Create admin user if doesn't exist
  if (!SD.exists(\"/users/admin\")) {
    SD.mkdir(\"/users/admin\");
    File adminFile = SD.open(\"/users/admin/pas.txt\", FILE_WRITE);
    if (adminFile) {
      adminFile.println(\"admin:\" + hashPassword(\"7428\"));
      adminFile.close();
    }
  }
}

void saveUser(const User& user) {
  String userDir = \"/users/\" + user.username;
  if (!SD.exists(userDir)) {
    SD.mkdir(userDir);
  }
  
  File pasFile = SD.open(userDir + \"/pas.txt\", FILE_WRITE);
  if (pasFile) {
    pasFile.println(user.username + \":\" + user.password);
    pasFile.close();
  }
  
  File userFile = SD.open(userDir + \"/\" + user.username + \".txt\", FILE_WRITE);
  if (userFile) {
    userFile.println(\"username:\" + user.username);
    userFile.println(\"avatar:\" + user.avatar);
    userFile.println(\"banned:\" + String(user.isBanned ? \"true\" : \"false\"));
    userFile.close();
  }
  
  if (user.isBanned && !user.banReason.isEmpty()) {
    File banFile = SD.open(userDir + \"/ban.txt\", FILE_WRITE);
    if (banFile) {
      banFile.println(\"reason:\" + user.banReason);
      banFile.println(\"time:\" + getCurrentTimestamp());
      banFile.close();
    }
  }
}

void loadUsers() {
  users.clear();
  File root = SD.open(\"/users\");
  if (!root) return;
  
  File file = root.openNextFile();
  while (file) {
    if (file.isDirectory()) {
      String username = file.name();
      User user;
      user.username = username;
      user.isOnline = false;
      user.isBanned = false;
      user.avatar = \"default.jpg\";
      
      // Load password
      File pasFile = SD.open(\"/users/\" + username + \"/pas.txt\");
      if (pasFile) {
        String line = pasFile.readStringUntil('\n');
        int colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
          user.password = line.substring(colonIndex + 1);
        }
        pasFile.close();
      }
      
      // Load user data
      File userFile = SD.open(\"/users/\" + username + \"/\" + username + \".txt\");
      if (userFile) {
        while (userFile.available()) {
          String line = userFile.readStringUntil('\n');
          if (line.startsWith(\"avatar:\")) {
            user.avatar = line.substring(7);
          } else if (line.startsWith(\"banned:\")) {
            user.isBanned = (line.substring(7) == \"true\");
          }
        }
        userFile.close();
      }
      
      // Load ban reason if banned
      if (user.isBanned) {
        File banFile = SD.open(\"/users/\" + username + \"/ban.txt\");
        if (banFile) {
          while (banFile.available()) {
            String line = banFile.readStringUntil('\n');
            if (line.startsWith(\"reason:\")) {
              user.banReason = line.substring(7);
            }
          }
          banFile.close();
        }
      }
      
      users.push_back(user);
    }
    file = root.openNextFile();
  }
  root.close();
}

void saveChatMessage(const ChatMessage& msg) {
  File chatFile = SD.open(\"/chat/messages.txt\", FILE_APPEND);
  if (chatFile) {
    chatFile.println(msg.timestamp + \"|\" + msg.username + \"|\" + msg.message + \"|\" + msg.attachment);
    chatFile.close();
  }
}

void loadChatHistory() {
  chatHistory.clear();
  File chatFile = SD.open(\"/chat/messages.txt\");
  if (chatFile) {
    while (chatFile.available()) {
      String line = chatFile.readStringUntil('\n');
      line.trim();
      if (line.length() > 0) {
        int pipe1 = line.indexOf('|');
        int pipe2 = line.indexOf('|', pipe1 + 1);
        int pipe3 = line.indexOf('|', pipe2 + 1);
        
        if (pipe1 > 0 && pipe2 > pipe1 && pipe3 > pipe2) {
          ChatMessage msg;
          msg.timestamp = line.substring(0, pipe1);
          msg.username = line.substring(pipe1 + 1, pipe2);
          msg.message = line.substring(pipe2 + 1, pipe3);
          msg.attachment = line.substring(pipe3 + 1);
          chatHistory.push_back(msg);
        }
      }
    }
    chatFile.close();
  }
}

// Authentication Functions
User* findUser(String username) {
  for (auto& user : users) {
    if (user.username == username) {
      return &user;
    }
  }
  return nullptr;
}

bool authenticateUser(String username, String password) {
  User* user = findUser(username);
  if (user && user->password == hashPassword(password) && !user->isBanned) {
    user->isOnline = true;
    user->lastActivity = millis();
    return true;
  }
  return false;
}

// WebSocket Event Handler
void onWsEvent(AsyncWebSocket * server, AsyncWebSocketClient * client, AwsEventType type, void * arg, uint8_t *data, size_t len) {
  if (type == WS_EVT_CONNECT) {
    Serial.printf(\"WebSocket client #%u connected from %s\n\", client->id(), client->remoteIP().toString().c_str());
  } else if (type == WS_EVT_DISCONNECT) {
    Serial.printf(\"WebSocket client #%u disconnected\n\", client->id());
    
    // Mark user as offline
    auto it = connectedClients.find(client->id());
    if (it != connectedClients.end()) {
      User* user = findUser(it->second);
      if (user) {
        user->isOnline = false;
      }
      connectedClients.erase(it);
    }
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo * info = (AwsFrameInfo*)arg;
    String msg = \"\";
    
    if (info->final && info->index == 0 && info->len == len) {
      if (info->opcode == WS_TEXT) {
        for (size_t i = 0; i < info->len; i++) {
          msg += (char) data[i];
        }
        
        // Parse JSON message
        DynamicJsonDocument doc(1024);
        deserializeJson(doc, msg);
        
        String type = doc[\"type\"];
        String username = doc[\"username\"];
        
        // Authenticate message
        auto it = connectedClients.find(client->id());
        if (it == connectedClients.end() && type != \"auth\") {
          return; // Not authenticated
        }
        
        if (type == \"auth\") {
          String password = doc[\"password\"];
          if (authenticateUser(username, password)) {
            connectedClients[client->id()] = username;
            
            // Send chat history
            DynamicJsonDocument response(4096);
            response[\"type\"] = \"chat_history\";
            JsonArray messages = response.createNestedArray(\"messages\");
            
            for (const auto& msg : chatHistory) {
              JsonObject msgObj = messages.createNestedObject();
              msgObj[\"username\"] = msg.username;
              msgObj[\"message\"] = msg.message;
              msgObj[\"timestamp\"] = msg.timestamp;
              msgObj[\"attachment\"] = msg.attachment;
            }
            
            String responseStr;
            serializeJson(response, responseStr);
            client->text(responseStr);
            
            // Notify others of user joining
            DynamicJsonDocument joinMsg(512);
            joinMsg[\"type\"] = \"user_joined\";
            joinMsg[\"username\"] = username;
            String joinStr;
            serializeJson(joinMsg, joinStr);
            ws.textAll(joinStr);
          } else {
            client->text(\"{\\"type\\":\\"auth_failed\\"}\");
          }
        } else if (type == \"chat_message\") {
          String message = sanitizeInput(doc[\"message\"]);
          if (message.length() > 100) {
            message = message.substring(0, 100);
          }
          
          ChatMessage chatMsg;
          chatMsg.username = username;
          chatMsg.message = message;
          chatMsg.timestamp = getCurrentTimestamp();
          chatMsg.attachment = doc[\"attachment\"];
          
          chatHistory.push_back(chatMsg);
          saveChatMessage(chatMsg);
          
          // Broadcast message
          DynamicJsonDocument broadcast(1024);
          broadcast[\"type\"] = \"new_message\";
          broadcast[\"username\"] = chatMsg.username;
          broadcast[\"message\"] = chatMsg.message;
          broadcast[\"timestamp\"] = chatMsg.timestamp;
          broadcast[\"attachment\"] = chatMsg.attachment;
          
          String broadcastStr;
          serializeJson(broadcast, broadcastStr);
          ws.textAll(broadcastStr);
        } else if (type == \"admin_command\" && username == \"admin\") {
          String command = doc[\"command\"];
          String target = doc[\"target\"];
          
          if (command == \"ban_user\") {
            User* targetUser = findUser(target);
            if (targetUser) {
              targetUser->isBanned = true;
              targetUser->banReason = doc[\"reason\"];
              saveUser(*targetUser);
              
              // Disconnect user
              for (auto& client_pair : connectedClients) {
                if (client_pair.second == target) {
                  AsyncWebSocketClient* targetClient = ws.client(client_pair.first);
                  if (targetClient) {
                    targetClient->text(\"{\\"type\\":\\"banned\\"}\");
                    targetClient->close();
                  }
                  break;
                }
              }
            }
          } else if (command == \"delete_message\") {
            // Implement message deletion logic
            // This would require message IDs to be more sophisticated
          }
        }
      }
    }
  }
}

// HTML Content
const char* loginHTML = R\"(
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>ESP32 Chat Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .welcome-text {
            font-size: 2rem;
            color: #333;
            margin-bottom: 1rem;
            font-weight: 600;
        }
        .subtitle {
            color: #666;
            margin-bottom: 2rem;
        }
        .login-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 1rem;
            cursor: pointer;
            transition: transform 0.2s;
            margin-bottom: 2rem;
        }
        .login-btn:hover {
            transform: translateY(-2px);
        }
        .login-form {
            display: none;
        }
        .form-group {
            margin-bottom: 1rem;
            text-align: left;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .submit-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 1rem;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s;
        }
        .submit-btn:hover {
            transform: translateY(-2px);
        }
        .error-msg {
            color: #e74c3c;
            margin-top: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <div class=\"login-container\">
        <div id=\"welcome-screen\">
            <h1 class=\"welcome-text\">Welcome</h1>
            <p class=\"subtitle\">ESP32 Chat Server</p>
            <button class=\"login-btn\" onclick=\"showLogin()\">Login</button>
        </div>
        
        <div id=\"login-form\" class=\"login-form\">
            <h2 style=\"margin-bottom: 1.5rem; color: #333;\">Login</h2>
            <form onsubmit=\"login(event)\">
                <div class=\"form-group\">
                    <label for=\"username\">Username:</label>
                    <input type=\"text\" id=\"username\" required>
                </div>
                <div class=\"form-group\">
                    <label for=\"password\">Password:</label>
                    <input type=\"password\" id=\"password\" required>
                </div>
                <button type=\"submit\" class=\"submit-btn\">Login</button>
                <div id=\"error-msg\" class=\"error-msg\">Invalid credentials</div>
            </form>
        </div>
    </div>

    <script>
        function showLogin() {
            document.getElementById('welcome-screen').style.display = 'none';
            document.getElementById('login-form').style.display = 'block';
        }

        function login(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    sessionStorage.setItem('username', username);
                    sessionStorage.setItem('token', data.token);
                    window.location.href = '/chat';
                } else {
                    document.getElementById('error-msg').style.display = 'block';
                }
            })
            .catch(error => {
                document.getElementById('error-msg').style.display = 'block';
            });
        }
    </script>
</body>
</html>
)\";

const char* chatHTML = R\"(
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Chat - ESP32 Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav-buttons {
            display: flex;
            gap: 1rem;
        }
        .nav-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .nav-btn:hover {
            background: rgba(255, 255, 255, 0.3);
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            max-height: calc(100vh - 60px);
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
            background: white;
        }
        .message {
            margin-bottom: 1rem;
            padding: 0.5rem;
            border-radius: 8px;
            background: #f8f9fa;
        }
        .message-header {
            font-weight: bold;
            color: #667eea;
            margin-bottom: 0.25rem;
        }
        .message-time {
            font-size: 0.8rem;
            color: #666;
            float: right;
        }
        .input-area {
            padding: 1rem;
            background: white;
            border-top: 1px solid #ddd;
            display: flex;
            gap: 0.5rem;
        }
        .message-input {
            flex: 1;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 20px;
            outline: none;
        }
        .send-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 20px;
            cursor: pointer;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
        }
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 2rem;
            border-radius: 10px;
            width: 90%;
            max-width: 500px;
        }
        .admin-panel {
            display: none;
        }
        .admin-controls {
            margin-top: 1rem;
        }
        .admin-btn {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 5px;
            cursor: pointer;
            margin: 0 5px;
        }
    </style>
</head>
<body>
    <div class=\"header\">
        <h1>ESP32 Chat</h1>
        <div class=\"nav-buttons\">
            <button class=\"nav-btn\" onclick=\"showBlog()\">Blog</button>
            <button class=\"nav-btn\" onclick=\"showSupport()\">Support</button>
            <button class=\"nav-btn\" onclick=\"showAccount()\">Account</button>
            <button class=\"nav-btn\" onclick=\"logout()\">Logout</button>
        </div>
    </div>

    <div class=\"chat-container\">
        <div class=\"messages\" id=\"messages\"></div>
        <div class=\"input-area\">
            <input type=\"text\" class=\"message-input\" id=\"messageInput\" placeholder=\"Type your message (max 100 chars)...\" maxlength=\"100\">
            <input type=\"file\" id=\"fileInput\" style=\"display: none;\" accept=\"image/*,video/*,.pdf,.doc,.docx\">
            <button onclick=\"document.getElementById('fileInput').click()\" style=\"padding: 10px; border: none; background: #28a745; color: white; border-radius: 20px; cursor: pointer;\">📎</button>
            <button class=\"send-btn\" onclick=\"sendMessage()\">Send</button>
        </div>
    </div>

    <!-- Modals -->
    <div id=\"blogModal\" class=\"modal\">
        <div class=\"modal-content\">
            <h2>Blog Posts</h2>
            <div id=\"blogContent\"></div>
            <button onclick=\"closeModal('blogModal')\">Close</button>
        </div>
    </div>

    <div id=\"supportModal\" class=\"modal\">
        <div class=\"modal-content\">
            <h2>Support</h2>
            <textarea id=\"supportMessage\" placeholder=\"Write to administrator...\" rows=\"5\" style=\"width: 100%; margin: 1rem 0;\"></textarea>
            <button onclick=\"sendSupport()\">Send</button>
            <button onclick=\"closeModal('supportModal')\">Close</button>
        </div>
    </div>

    <div id=\"accountModal\" class=\"modal\">
        <div class=\"modal-content\">
            <h2>Account Settings</h2>
            <div>
                <label>Change Avatar:</label>
                <input type=\"file\" id=\"avatarInput\" accept=\"image/*\">
                <button onclick=\"uploadAvatar()\">Upload</button>
            </div>
            <div id=\"adminPanel\" class=\"admin-panel\">
                <h3>Admin Controls</h3>
                <div class=\"admin-controls\">
                    <input type=\"text\" id=\"banUsername\" placeholder=\"Username to ban\">
                    <input type=\"text\" id=\"banReason\" placeholder=\"Ban reason\">
                    <button class=\"admin-btn\" onclick=\"banUser()\">Ban User</button>
                </div>
            </div>
            <button onclick=\"closeModal('accountModal')\">Close</button>
        </div>
    </div>

    <script>
        let ws;
        let username = sessionStorage.getItem('username');

        if (!username) {
            window.location.href = '/';
        }

        function connectWebSocket() {
            ws = new WebSocket('ws://' + window.location.host + '/ws');
            
            ws.onopen = function() {
                console.log('Connected to WebSocket');
                // Authenticate
                ws.send(JSON.stringify({
                    type: 'auth',
                    username: username,
                    password: sessionStorage.getItem('token')
                }));
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'chat_history') {
                    displayChatHistory(data.messages);
                } else if (data.type === 'new_message') {
                    displayMessage(data);
                } else if (data.type === 'user_joined') {
                    displaySystemMessage(data.username + ' joined the chat');
                } else if (data.type === 'banned') {
                    alert('You have been banned from the server');
                    logout();
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket connection closed');
                setTimeout(connectWebSocket, 3000);
            };
        }

        function displayChatHistory(messages) {
            const messagesDiv = document.getElementById('messages');
            messagesDiv.innerHTML = '';
            messages.forEach(msg => displayMessage(msg));
        }

        function displayMessage(msg) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            
            messageDiv.innerHTML = `
                <div class=\"message-header\">
                    ${msg.username}
                    <span class=\"message-time\">${msg.timestamp}</span>
                </div>
                <div>${msg.message}</div>
                ${msg.attachment ? `<div><em>Attachment: ${msg.attachment}</em></div>` : ''}
            `;
            
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        function displaySystemMessage(message) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            messageDiv.style.background = '#e3f2fd';
            messageDiv.innerHTML = `<em>${message}</em>`;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        function sendMessage() {
            const input = document.getElementById('messageInput');
            const message = input.value.trim();
            
            if (message && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'chat_message',
                    username: username,
                    message: message,
                    attachment: ''
                }));
                input.value = '';
            }
        }

        function showBlog() {
            document.getElementById('blogModal').style.display = 'block';
            // Load blog posts
            fetch('/api/blog')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('blogContent').innerHTML = 
                        data.posts.map(post => `<div style=\"margin: 1rem 0; padding: 1rem; background: #f8f9fa; border-radius: 5px;\">${post}</div>`).join('');
                });
        }

        function showSupport() {
            document.getElementById('supportModal').style.display = 'block';
        }

        function showAccount() {
            document.getElementById('accountModal').style.display = 'block';
            if (username === 'admin') {
                document.getElementById('adminPanel').style.display = 'block';
            }
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        function logout() {
            sessionStorage.clear();
            window.location.href = '/';
        }

        function sendSupport() {
            const message = document.getElementById('supportMessage').value;
            if (message.trim()) {
                fetch('/api/support', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: message, username: username })
                });
                alert('Support message sent!');
                closeModal('supportModal');
            }
        }

        function banUser() {
            const targetUser = document.getElementById('banUsername').value;
            const reason = document.getElementById('banReason').value;
            
            if (targetUser && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'admin_command',
                    command: 'ban_user',
                    username: username,
                    target: targetUser,
                    reason: reason
                }));
                alert('User banned!');
            }
        }

        // Event listeners
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });

        // Initialize WebSocket connection
        connectWebSocket();

        // Show admin panel if admin
        if (username === 'admin') {
            document.getElementById('adminPanel').style.display = 'block';
        }
    </script>
</body>
</html>
)\";

void setup() {
  Serial.begin(115200);
  
  // Initialize button
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  
  // Initialize SD card
  initSD();
  
  // Load users from SD card
  loadUsers();
  loadChatHistory();
  
  // Setup WiFi Access Point
  WiFi.softAP(ap_ssid, ap_password);
  Serial.println(\"WiFi AP started\");
  Serial.print(\"IP address: \");
  Serial.println(WiFi.softAPIP());
  
  // Setup WebSocket
  ws.onEvent(onWsEvent);
  server.addHandler(&ws);
  
  // Setup routes
  server.on(\"/\", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (!rateLimitCheck(request->client()->remoteIP().toString())) {
      request->send(429, \"text/plain\", \"Too Many Requests\");
      return;
    }
    request->send(200, \"text/html\", loginHTML);
  });
  
  server.on(\"/chat\", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (!rateLimitCheck(request->client()->remoteIP().toString())) {
      request->send(429, \"text/plain\", \"Too Many Requests\");
      return;
    }
    request->send(200, \"text/html\", chatHTML);
  });
  
  server.on(\"/api/login\", HTTP_POST, [](AsyncWebServerRequest *request) {
    if (!rateLimitCheck(request->client()->remoteIP().toString())) {
      request->send(429, \"application/json\", \"{\\"success\\":false,\\"error\\":\\"Too many requests\\"}\");
      return;
    }
  }, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
    String body = \"\";
    for (size_t i = 0; i < len; i++) {
      body += (char)data[i];
    }
    
    DynamicJsonDocument doc(512);
    deserializeJson(doc, body);
    
    String username = sanitizeInput(doc[\"username\"]);
    String password = doc[\"password\"];
    
    if (authenticateUser(username, password)) {
      request->send(200, \"application/json\", \"{\\"success\\":true,\\"token\\":\\"\" + password + \"\\"}\");
    } else {
      request->send(401, \"application/json\", \"{\\"success\\":false,\\"error\\":\\"Invalid credentials\\"}\");
    }
  });
  
  server.on(\"/api/blog\", HTTP_GET, [](AsyncWebServerRequest *request) {
    DynamicJsonDocument doc(2048);
    JsonArray posts = doc.createNestedArray(\"posts\");
    
    // Load blog posts from SD card
    File blogFile = SD.open(\"/config/blog.txt\");
    if (blogFile) {
      while (blogFile.available()) {
        String post = blogFile.readStringUntil('\n');
        if (post.length() > 0) {
          posts.add(post);
        }
      }
      blogFile.close();
    }
    
    String response;
    serializeJson(doc, response);
    request->send(200, \"application/json\", response);
  });
  
  server.on(\"/api/support\", HTTP_POST, [](AsyncWebServerRequest *request) {
    // Handle support requests
  }, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
    String body = \"\";
    for (size_t i = 0; i < len; i++) {
      body += (char)data[i];
    }
    
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, body);
    
    String message = sanitizeInput(doc[\"message\"]);
    String username = sanitizeInput(doc[\"username\"]);
    
    // Save support request
    File supportFile = SD.open(\"/logs/support.txt\", FILE_APPEND);
    if (supportFile) {
      supportFile.println(getCurrentTimestamp() + \" - \" + username + \": \" + message);
      supportFile.close();
    }
    
    request->send(200, \"application/json\", \"{\\"success\\":true}\");
  });
  
  // File upload handler
  server.on(\"/api/upload\", HTTP_POST, [](AsyncWebServerRequest *request) {
    request->send(200, \"application/json\", \"{\\"success\\":true}\");
  }, [](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final) {
    static File uploadFile;
    
    if (!index) {
      String path = \"/uploads/\" + filename;
      uploadFile = SD.open(path, FILE_WRITE);
    }
    
    if (uploadFile) {
      uploadFile.write(data, len);
    }
    
    if (final) {
      uploadFile.close();
    }
  });
  
  // Start server
  server.begin();
  Serial.println(\"HTTP server started\");
  
  // Initialize NTP for timestamps
  configTime(0, 0, \"pool.ntp.org\");
}

void loop() {
  // Handle button press for manual operations
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50); // Debounce
    if (digitalRead(BUTTON_PIN) == LOW) {
      Serial.println(\"Button pressed - System status:\");
      Serial.printf(\"Connected clients: %d\n\", ws.count());
      Serial.printf(\"Registered users: %d\n\", users.size());
      Serial.printf(\"Chat messages: %d\n\", chatHistory.size());
      
      while (digitalRead(BUTTON_PIN) == LOW) {
        delay(10);
      }
    }
  }
  
  // Clean up offline users periodically
  static unsigned long lastCleanup = 0;
  if (millis() - lastCleanup > 60000) { // Every minute
    lastCleanup = millis();
    
    for (auto& user : users) {
      if (user.isOnline && (millis() - user.lastActivity > 300000)) { // 5 minutes timeout
        user.isOnline = false;
      }
    }
  }
  
  // Handle WebSocket cleanup
  ws.cleanupClients();
  
  delay(10);
}"
Observation: Create successful: /app/ESP32_ChatServer.ino
