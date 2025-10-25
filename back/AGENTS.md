# Conventions for this repo

## Error handling

- Always log errors using our logger package `logger`.
- Never swallow errors; return early with context.


## Shared string utilities

- Prefer `stringutils` for all string ops.
- You may add function in `stringutils` if you think they should be commonly used.

## Configuration

- use our package `config` for configuration
- you may add new config values in our configuration, always provide the default
