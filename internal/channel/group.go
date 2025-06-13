package channel

import "gorm.io/gorm"

type Group struct {
    gorm.Model
    Name     string
    Channels []Channel
}
