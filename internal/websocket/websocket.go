package websocket

import (
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
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 16384
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	Conn      *websocket.Conn
	UserID    string
	Send      chan interface{}
	Connected bool
	mu        sync.RWMutex
}

type Hub struct {
	clients        map[*Client]bool
	broadcast      chan []byte
	register       chan *Client
	unregister     chan *Client
	mu             sync.RWMutex
	userClients    map[string]*Client
	broadcastQueue chan []byte
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
	Status string `json:"status"`
}

var GlobalHub = &Hub{
	clients:        make(map[*Client]bool),
	userClients:    make(map[string]*Client),
	broadcast:      make(chan []byte),
	register:       make(chan *Client),
	unregister:     make(chan *Client),
	broadcastQueue: make(chan []byte, 512),
}

func (h *Hub) Run() {
	onlineUsersTicker := time.NewTicker(30 * time.Second)
	defer onlineUsersTicker.Stop()

	// Set the voice broadcaster
	voice.SetBroadcaster(h)

	go h.broadcastLoop()

	for {
		select {
        case client := <-h.register:
            h.mu.Lock()

            if existingClient, exists := h.userClients[client.UserID]; exists {
                log.Printf("User %s already connected, closing existing connection", client.UserID)
                if _, ok := h.clients[existingClient]; ok {
                    delete(h.clients, existingClient)
                    delete(h.userClients, client.UserID) // Clean up user mapping immediately

                    // Mark existing client as disconnected before closing
                    existingClient.mu.Lock()
                    existingClient.Connected = false
                    existingClient.mu.Unlock()

                    // Close existing connection in a goroutine to avoid blocking
                    go func(oldClient *Client) {
                        close(oldClient.Send)
                        oldClient.Conn.Close()
                        // Clean up voice connections for the old connection
                        voice.DisconnectUserFromAllVoiceRooms(oldClient.UserID)
                    }(existingClient)
                }
            }

            // Add new client
            h.clients[client] = true
            h.userClients[client.UserID] = client
            client.mu.Lock()
            client.Connected = true
            client.mu.Unlock()

            h.mu.Unlock()
            log.Printf("User %s connected", client.UserID)

		case client := <-h.unregister:
            h.mu.Lock()
            if _, ok := h.clients[client]; ok {
                delete(h.clients, client)
                delete(h.userClients, client.UserID)

                // Only close if not already closed
                select {
                case <-client.Send:
                    // Channel already closed
                default:
                    close(client.Send)
                }

                client.mu.Lock()
                client.Connected = false
                client.mu.Unlock()
            }
            h.mu.Unlock()

            log.Printf("User %s disconnected, cleaning up voice rooms", client.UserID)

            go func(userID string) {
                voice.DisconnectUserFromAllVoiceRooms(userID)
                h.BroadcastMessage("user_status", UserStatusData{
                    UserID: userID,
                    Status: "offline",
                })
            }(client.UserID)

		case message := <-h.broadcast:
			select {
			case h.broadcastQueue <- message:
			default:
				log.Printf("Broadcast queue full, dropping message")
			}
		case <-onlineUsersTicker.C:
			h.broadcastOnlineUsers()
		}
	}
}

func (h *Hub) broadcastLoop() {
	for message := range h.broadcastQueue {
		h.mu.RLock()
		clients := make([]*Client, 0, len(h.clients))
		for client := range h.clients {
			clients = append(clients, client)
		}
		h.mu.RUnlock()

		for _, client := range clients {
			select {
			case client.Send <- message:
			default:
				log.Printf("Client %s send channel full during broadcast, disconnecting", client.UserID)
				h.unregister <- client
			}
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

func (h *Hub) SendMessageToUser(userID string, messageType string, data interface{}) {
	h.mu.RLock()
	client, exists := h.userClients[userID]
	h.mu.RUnlock()

	if exists {
		client.mu.RLock()
		connected := client.Connected
		client.mu.RUnlock()

		if connected {
			message := Message{
				Type: messageType,
				Data: data,
			}

			jsonData, err := json.Marshal(message)
			if err != nil {
				log.Printf("Error marshaling message to user %s: %v", userID, err)
				return
			}

			select {
			case client.Send <- jsonData:
			default:
				log.Printf("Send channel full for user %s, disconnecting", userID)
				h.unregister <- client
			}
		}
	}
}

func (h *Hub) IsUserConnected(userID string) bool {
	h.mu.RLock()
	client, exists := h.userClients[userID]
	h.mu.RUnlock()

	if !exists {
		return false
	}

	client.mu.RLock()
	connected := client.Connected
	client.mu.RUnlock()

	return connected
}

func (c *Client) readPump() {
	defer func() {
        c.mu.Lock()
        c.Connected = false
        c.mu.Unlock()

        // Only unregister if this client is still the active one for this user
        GlobalHub.mu.RLock()
        currentClient, exists := GlobalHub.userClients[c.UserID]
        isCurrentClient := exists && currentClient == c
        GlobalHub.mu.RUnlock()

        if isCurrentClient {
            GlobalHub.unregister <- c
        }
        c.Conn.Close()
    }()

    c.Conn.SetReadLimit(maxMessageSize)
    c.Conn.SetReadDeadline(time.Now().Add(pongWait))
    c.Conn.SetPongHandler(func(string) error {
        c.Conn.SetReadDeadline(time.Now().Add(pongWait))
        return nil
    })

	for {
		c.mu.RLock()
		if !c.Connected {
			c.mu.RUnlock()
			break
		}
		c.mu.RUnlock()

		messageType, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error for user %s: %v", c.UserID, err)
			}
			break
		}

		if messageType == websocket.TextMessage {
			var msg Message
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Printf("Error unmarshaling message from %s: %v", c.UserID, err)
				continue
			}

			// Handle WebRTC signaling messages
			if c.isWebRTCMessage(msg.Type) {
				if data, ok := msg.Data.(map[string]interface{}); ok {
					if err := voice.HandleSignalingMessage(c.UserID, msg.Type, data); err != nil {
						log.Printf("Error handling signaling message from %s: %v", c.UserID, err)
					}
				}
			}

			// Handle voice state updates
			if msg.Type == "speaking_update" {
				if data, ok := msg.Data.(map[string]interface{}); ok {
					if channelID, ok := data["channel_id"].(float64); ok {
						if isSpeaking, ok := data["is_speaking"].(bool); ok {
							voice.UpdateSpeakingStatus(c.UserID, uint(channelID), isSpeaking)
						}
					}
				}
			}

			if msg.Type == "webrtc_connection_status" {
				if data, ok := msg.Data.(map[string]interface{}); ok {
					if channelID, ok := data["channel_id"].(float64); ok {
						if connected, ok := data["connected"].(bool); ok {
							voice.UpdateWebRTCConnectionStatus(c.UserID, uint(channelID), connected)
						}
					}
				}
			}

			if msg.Type == "connection_quality" {
				if data, ok := msg.Data.(map[string]interface{}); ok {
					if channelID, ok := data["channel_id"].(float64); ok {
						if quality, ok := data["quality"].(string); ok {
							voice.UpdateConnectionQuality(c.UserID, uint(channelID), quality)
						}
					}
				}
			}
		}
	}
}

func (c *Client) isWebRTCMessage(msgType string) bool {
	webrtcTypes := []string{
		"offer", "answer", "ice-candidate",
		"peer-connect", "peer-disconnect",
		"webrtc_stats", // Add stats reporting
	}

	for _, t := range webrtcTypes {
		if msgType == t {
			return true
		}
	}
	return false
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
			c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.mu.RLock()
			connected := c.Connected
			c.mu.RUnlock()
			if !connected {
				return
			}

			switch msg := message.(type) {
			case []byte:
				if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					log.Printf("Error writing text message to %s: %v", c.UserID, err)
					return
				}
			default:
				log.Printf("Unknown message type in send channel for user %s: %T", c.UserID, message)
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			c.mu.RLock()
			connected := c.Connected
			c.mu.RUnlock()
			if !connected {
				return
			}
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Error sending ping to %s: %v", c.UserID, err)
				return
			}
		}
	}
}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		auth := r.Header.Get("Authorization")
		if auth != "" && len(auth) > 7 && auth[:7] == "Bearer " {
			userID = auth[7:]
		}
	}

	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

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
		Send:   make(chan interface{}, 32),
	}

	GlobalHub.register <- client

	go client.writePump()
	go client.readPump()

	GlobalHub.BroadcastMessage("user_status", UserStatusData{
		UserID: client.UserID,
		Status: "online",
	})
}
