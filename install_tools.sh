#!/usr/bin/bash

TOOLS_URL=https://www.dropbox.com/s/d8y5skuzai9j2gk/tools.zip?dl=0

wget ${TOOLS_URL} -o tools.zip

unzip -d tools/ tools.zip
rm tools.zip
echo "Tools installed successfully!"
