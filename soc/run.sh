#!/bin/bash

cd ../app
echo "Start Flask App"
python app.py &

cd ../soc
echo "Start SOC"
python soc.py