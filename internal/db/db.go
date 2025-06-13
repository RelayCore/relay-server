package db

import (
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
)

var DB *gorm.DB

func Init() error {
	err := os.MkdirAll("data", 0755)
    if err != nil {
        return err
    }

    DB, err = gorm.Open(sqlite.Dialector{
        DriverName: "sqlite",
        DSN:        "data/chat.db",
    }, &gorm.Config{})

    return err
}