
# Conventions for package auth

## Database access

Use `store.go` for any code accessing the database. 
You are not required to put all methods of `Store` object inside `store.go` file. If they are business similar with functionality in a given file put them in the same file.

## Model

Use `model.go` for any types regarding the auth domain model.

yse `model_http.go` for defining request, response payload of http endpoints. Use prefixes `Request`, `Response` and path name when composing paylod type name. 
Example:
- if http endpoint is `/login` name request payload type  'RequestLogin`, name response payload type `ResponseLogin`. 

