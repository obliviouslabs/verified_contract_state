#!/bin/sh
#1) Make sure .env exists and contains GET_URL:

if [ ! -f .env ]; then
  echo "Missing .env file"
  exit 1
fi

# Create checkpoints folder if it doesn't exist
[ ! -d checkpoints ] && mkdir checkpoints

