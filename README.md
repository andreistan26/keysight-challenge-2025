# Keysight Challenge 2025 - Andrei Stan & Iulian Alexa

## Intro
Welcome to the Keysgiht Challenge 2025. In this challenge you will have to run code on the GPU and demonstrate your skills in parallelizing the code for better performance.

The main description of the task is in this [document](https://docs.google.com/document/d/1-A59iiqdzbKEcdTZGfll-y3Vl6Kw7nMEBiraD2W86pU/edit?usp=sharing).

### On a Linux System
    * Build the gpu-router application
      git clone $YOUR_GITHUB_FORK
      cd keysight-challenge-2025
      mkdir build
      cd build
      cmake ..
      make VERBOSE=1

    * Run the program
      ./gpu-router <path-to-pcap-file> <name-of-output-interface>
      ex: ./gpu-router capture1.pcap eth0

    * Clean the program
      make clean


## Descriere

* Avem toate nodurile facute

* Extra: bonusurile din cerinta, receive de pe socket, ttl decrement, recalculare checksum(ipv4, ivp6 n-are)
* macro TIME_PROF care masoara timpul de rutare pentru fiecare pachet
* pentru timpi: TIME_PROF=1 make
