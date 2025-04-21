#!/usr/bin/env bash

#!/bin/bash

# Check if the title and directory are provided
if [ $# -ne 2 ]; then
  echo "Usage: $0 <post-title> <directory>"
  exit 1
fi

# Get the post title and directory from arguments
POST_TITLE=$1
DIRECTORY=$2
DATE=$(date +%Y-%m-%d)
FILENAME=$(echo $POST_TITLE | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd '[:alnum:]-')
FILE_PATH="_posts/$DIRECTORY"

# Create the directory if it doesn't exist
mkdir -p $FILE_PATH

# Create the post file
POST_FILE="$FILE_PATH/$DATE-$FILENAME.md"

# Add the front matter to the post file
echo -e "---\nlayout: single\ntitle: \"$POST_TITLE\"\ndate: $DATE 00:00:00 +0000\ncategories: [blog]\ntags: [jekyll, post]\nauthor_profile: true\ntoc: true\ntoc_sticky: true\nexcerpt: \"A quick summary of this post.\"\nheader:\n  overlay_image: /assets/images/header-banner.jpg\n  overlay_filter: 0.3\n  caption: \"Optional header image caption\"\n---\n\nStart writing your post here!" > $POST_FILE

# Notify the user
echo "Post created successfully: $POST_FILE"

