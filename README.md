# Warbird Crypto JS

A simple tool written in Node.js that helps you decrypt malware samples abusing Microsoft Warbird to encrypt its payloads.  

## Usage

This is a library script. You'll have to reverse engineer the sample and locate its warbird parameters and the encrypted data.  

There is a sample script in the `example` folder. It decrypts the stager chellcode in the [infamous Notepad++ supply chain malware](https://www.virustotal.com/gui/file/b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3).  

## Disclaimer

Warbird algorithms belong to Microsoft. This tool is solely aimed at helping analysts decrypt malware payloads.  

This implementation is derived from [gmh5225/warbird-example](https://github.com/gmh5225/warbird-example).  
