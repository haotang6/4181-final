#!/bin/bash

mkdir messages
mkdir tmp
mkdir certs

input=("bob" "addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")

for i in ${input[@]}
do
	mkdir messages/$i
done