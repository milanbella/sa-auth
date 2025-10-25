
# Conventions for package auth

## Database access

Use `store.go` for any code accessing the database. 
You are not required to put all methods of `Store` object inside `store.go` file. If they are business similar with functionality in a given file put them in the same file.

## Model

Use `model.go` fro any types regarding the auth domain model.

