#!/bin/bash

iteration=1

while true; do
    echo
    echo "---------------"
    echo
    echo "Iteration $iteration"
    
    npm run build
    
    if git diff --quiet bundle.js; then
        echo "No changes in bundle.js"
    else
        echo "Git diff detected in bundle.js - failing at iteration $iteration"
        exit 1
    fi
    
    ((iteration++))
done