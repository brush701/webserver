package main

import (
    "github.com/jinzhu/gorm"
)

type Subscriber struct {
    gorm.Model
    Name string
    Email string
  }
