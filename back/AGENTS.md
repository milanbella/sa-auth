# Conventions for this repo

## Error handling

- Always log errors using our logger package `logger`.
- It is very important that if function returns error that ypu always log the error. Thus when we look to the log we shall also have recorded the stack calls leading to the errored function.
- Never swallow errors; return early with context.


## Shared string utilities

- Prefer `stringutils` for all string ops.
- You may add function in `stringutils` if you think they should be commonly used.

## Configuration

- use our package `config` for configuration
- you may add new config values in our configuration, always provide the default
