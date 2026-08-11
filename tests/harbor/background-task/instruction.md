Start the requested TCP service with `run_terminal_command` using
`background=true`, leave it running for the shared verifier, and then finish.
The service must listen on `127.0.0.1:18765` and return exactly
`NANO_BACKGROUND_OK` followed by a newline to every client.
