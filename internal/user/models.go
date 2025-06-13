package user

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PublicKeyType is a custom type for storing ed25519.PublicKey in the database
type PublicKeyType []byte

func (pk PublicKeyType) Value() (driver.Value, error) {
    return base64.StdEncoding.EncodeToString(pk), nil
}

func (pk *PublicKeyType) Scan(value interface{}) error {
    if value == nil {
        return nil
    }

    str, ok := value.(string)
    if !ok {
        return fmt.Errorf("cannot scan %T into PublicKeyType", value)
    }

    decoded, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return err
    }

    *pk = decoded
    return nil
}

// RoleIDsType is a custom type for storing role IDs as JSON in the database
type RoleIDsType []string

func (r RoleIDsType) Value() (driver.Value, error) {
    return json.Marshal(r)
}

func (r *RoleIDsType) Scan(value interface{}) error {
    if value == nil {
        return nil
    }

    bytes, ok := value.([]byte)
    if !ok {
        return fmt.Errorf("cannot scan %T into RoleIDsType", value)
    }

    return json.Unmarshal(bytes, r)
}

// UserModel represents the database model for users
type UserModel struct {
    gorm.Model
    ID        string        `gorm:"primaryKey"`
    Username  string        `gorm:"uniqueIndex"`
    Nickname  string
    PublicKey PublicKeyType
    RoleIDs   RoleIDsType
}

// InviteModel represents the database model for invites
type InviteModel struct {
    gorm.Model
    Code      string    `gorm:"primaryKey"`
    CreatedBy string
    CreatedAt time.Time
    ExpiresAt *time.Time
    MaxUses   int
    Uses      int
}

// RoleModel represents the database model for roles
type RoleModel struct {
    gorm.Model
    ID          string `gorm:"primaryKey"`
    Name        string
    Color       string
    Rank        int
    Permissions string // JSON string of permissions
    Assignable  bool
}