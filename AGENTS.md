This is a project to implement a ssh like terminal for remote login using hppk(https://github.com/xtaci/hppk) for authentication and qpp(https://github.com/xtaci/qpp) for encryption.

It uses protobuf for message serialization and deserialization.

It supports client & server mode in a single binary.

The client connects to the server using hppk for authentication and establishes a secure channel using qpp. Once connected, the client can send terminal commands to the server, which executes them and returns the output back to the client. The project aims to provide a secure and efficient way to remotely access and manage servers via terminal commands.

The server supports multiple concurrent client connections, allowing multiple users to access the server simultaneously.

client.go and server.go handles client and server commands respectively.

session.go implements the terminal session handling, including secure channel establishment, reading/writing from/to terminal, handling terminal resize events etc.

file.go implements file upload/download feature.

channel.go implements the authenticated and encrypted channel using HMAC for message authentication, and QPP for encryption.

The crypto/ directory has auxciliary cryptographic functions, including loading private keys from encrypted json file, signature decoding/encoding etc.

register.go loads client public key and ID from config file and command line arguments
