package websocket

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"relay-server/internal/user"
	"relay-server/internal/voice"

	"github.com/gorilla/websocket"
)

const (
    // Time allowed to write a message to the peer.
    writeWait = 10 * time.Second

    // Time allowed to read the next pong message from the peer.
    // Must be greater than pingPeriod.
    pongWait = 60 * time.Second

    // Send pings to peer with this period. Must be less than pongWait.
    pingPeriod = (pongWait * 9) / 10

    // Maximum message size allowed from peer.
    maxMessageSize = 1024 // Adjusted for general use, can be tuned
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // Allow connections from any origin
    },
}

type Client struct {
    Conn   *websocket.Conn
    UserID string
    Send   chan []byte
}

type Hub struct {
    clients    map[*Client]bool
    broadcast  chan []byte
    register   chan *Client
    unregister chan *Client
    mu         sync.RWMutex
    // Add callback for voice data processing
    VoiceDataHandler func(userID string, channelID uint, audioData []byte) error
}

type Message struct {
    Type string      `json:"type"`
    Data interface{} `json:"data"`
}

type MessageBroadcast struct {
    ID        uint      `json:"id"`
    ChannelID uint      `json:"channel_id"`
    AuthorID  string    `json:"author_id"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
    Username  string    `json:"username,omitempty"`
    Nickname  string    `json:"nickname,omitempty"`
}

type OnlineUsersData struct {
    OnlineUsers []string `json:"online_users"`
    UserCount   int      `json:"user_count"`
}

type UserStatusData struct {
    UserID string `json:"user_id"`
    Status string `json:"status"` // "online" or "offline"
}

var GlobalHub = &Hub{
    clients:    make(map[*Client]bool),
    broadcast:  make(chan []byte),
    register:   make(chan *Client),
    unregister: make(chan *Client),
}

// SetVoiceDataHandler sets the callback for processing voice data
func (h *Hub) SetVoiceDataHandler(handler func(userID string, channelID uint, audioData []byte) error) {
    h.VoiceDataHandler = handler
}

func (h *Hub) Run() {
    onlineUsersTicker := time.NewTicker(30 * time.Second)
    defer onlineUsersTicker.Stop()

    for {
        select {
        case client := <-h.register:
            h.mu.Lock()
            h.clients[client] = true
            h.mu.Unlock()
            log.Printf("User %s connected", client.UserID)

        case client := <-h.unregister:
            h.mu.Lock()
            if _, ok := h.clients[client]; ok {
                delete(h.clients, client)
                close(client.Send)
            }
            h.mu.Unlock()
            log.Printf("User %s disconnected and removed from voice rooms", client.UserID)
            voice.DisconnectUserFromAllVoiceRooms(client.UserID)
            h.BroadcastMessage("user_status", UserStatusData{
                UserID: client.UserID,
                Status: "offline",
            })

        case message := <-h.broadcast:
            h.mu.RLock()
            for client := range h.clients {
                select {
                case client.Send <- message:
                default:
                    close(client.Send)
                    delete(h.clients, client)
                }
            }
            h.mu.RUnlock()

        case <-onlineUsersTicker.C:
            h.broadcastOnlineUsers()
        }
    }
}

func (h *Hub) broadcastOnlineUsers() {
    h.mu.RLock()
    onlineUsers := make([]string, 0, len(h.clients))
    for client := range h.clients {
        onlineUsers = append(onlineUsers, client.UserID)
    }
    h.mu.RUnlock()

    message := Message{
        Type: "online_users",
        Data: OnlineUsersData{
            OnlineUsers: onlineUsers,
            UserCount:   len(onlineUsers),
        },
    }

    data, err := json.Marshal(message)
    if err != nil {
        log.Printf("Error marshaling online users: %v", err)
        return
    }

    go func() {
        h.broadcast <- data
    }()
}

func (h *Hub) GetOnlineUsers() []string {
    h.mu.RLock()
    defer h.mu.RUnlock()

    onlineUsers := make([]string, 0, len(h.clients))
    for client := range h.clients {
        onlineUsers = append(onlineUsers, client.UserID)
    }
    return onlineUsers
}

func (h *Hub) IsUserOnline(userID string) bool {
    h.mu.RLock()
    defer h.mu.RUnlock()

    for client := range h.clients {
        if client.UserID == userID {
            return true
        }
    }
    return false
}

func (h *Hub) BroadcastMessage(messageType string, data interface{}) {
    message := Message{
        Type: messageType,
        Data: data,
    }

    jsonData, err := json.Marshal(message)
    if err != nil {
        log.Printf("Error marshaling broadcast message: %v", err)
        return
    }

    h.mu.RLock()
    log.Printf("Broadcasting %s to %d clients", messageType, len(h.clients))
    h.mu.RUnlock()

    h.broadcast <- jsonData
}

func (h *Hub) BroadcastMessageWithUserInfo(messageType string, messageData interface{}) {
    message := Message{
        Type: messageType,
        Data: messageData,
    }

    jsonData, err := json.Marshal(message)
    if err != nil {
        log.Printf("Error marshaling broadcast message: %v", err)
        return
    }

    h.broadcast <- jsonData
}

func (c *Client) readPump() {
    defer func() {
        // Clean up voice room participation before unregistering
        voice.DisconnectUserFromAllVoiceRooms(c.UserID)
        GlobalHub.unregister <- c
        c.Conn.Close()
    }()
    c.Conn.SetReadLimit(maxMessageSize)
    c.Conn.SetReadDeadline(time.Now().Add(pongWait))
    c.Conn.SetPongHandler(func(string) error {
        c.Conn.SetReadDeadline(time.Now().Add(pongWait))
        return nil
    })

    for {
        messageType, message, err := c.Conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("WebSocket error: %v", err)
            }
            break
        }

        if messageType == websocket.BinaryMessage {
            // Handle voice data using callback
            if len(message) >= 8 && GlobalHub.VoiceDataHandler != nil {
                // First 4 bytes: channel ID, next 4 bytes: data length
                channelID := binary.LittleEndian.Uint32(message[:4])
                dataLength := binary.LittleEndian.Uint32(message[4:8])

                if len(message) >= int(8+dataLength) {
                    audioData := message[8:8+dataLength]
                    if err := GlobalHub.VoiceDataHandler(c.UserID, uint(channelID), audioData); err != nil {
                        log.Printf("Error processing voice data: %v", err)
                    }
                }
            }
        } else {
            // Handle text messages
            var msg Message
            if err := json.Unmarshal(message, &msg); err != nil {
                log.Printf("Error unmarshaling message: %v", err)
                continue
            }
        }
    }
}

func (c *Client) writePump() {
    ticker := time.NewTicker(pingPeriod)
    defer func() {
        ticker.Stop()
        c.Conn.Close()
    }()

    for {
        select {
        case message, ok := <-c.Send:
            c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
            if !ok {
                // The Hub closed the channel.
                if err := c.Conn.WriteMessage(websocket.CloseMessage, []byte{}); err != nil {
                    log.Printf("Error writing close message to %s: %v", c.UserID, err)
                }
                return
            }

            if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
                log.Printf("Error writing text message to %s: %v", c.UserID, err)
                return
            }
        case <-ticker.C:
            c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
            if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
                log.Printf("Error sending ping to %s: %v", c.UserID, err)
                return
            }
        }
    }
}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Get user ID from query parameter or header
    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        // Try to get from Authorization header
        auth := r.Header.Get("Authorization")
        if auth != "" && len(auth) > 7 && auth[:7] == "Bearer " {
            userID = auth[7:]
        }
    }

    if userID == "" {
        http.Error(w, "User ID required", http.StatusBadRequest)
        return
    }

    // Verify user exists
    user.Mu.RLock()
    _, exists := user.Users[userID]
    user.Mu.RUnlock()

    if !exists {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error: %v", err)
        return
    }

    client := &Client{
        Conn:   conn,
        UserID: userID,
        Send:   make(chan []byte, 256),
    }

    GlobalHub.register <- client

    go client.writePump()
    go client.readPump()

    GlobalHub.BroadcastMessage("user_status", UserStatusData{
        UserID: client.UserID,
        Status: "online",
    })
}
