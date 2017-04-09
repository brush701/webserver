package main

import (
    "github.com/jinzhu/gorm"
)

type User struct {
    gorm.Model
    UserName string
    Role string
    Email string
    PasswordHash []byte
  }
