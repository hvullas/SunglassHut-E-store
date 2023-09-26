package db

import (
	"github.com/go-redis/redis"
)

var RedisClient *redis.Client

func ConnectRedis() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     "redis-13413.c266.us-east-1-3.ec2.cloud.redislabs.com:13413",
		Password: "Ullasa@21",
		DB:       0,
	})
}
