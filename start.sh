#!/bin/bash

# Create directories if they don't exist
mkdir -p ./postgres
mkdir -p ./redis-data

# Start Docker Compose
docker-compose up -d
