package api.access

default allow = false

# Check if the application name, environment, client ID, API name, and version match
allow {
    input.applicationName == "{{ .ApplicationName }}"
    input.environment == "{{ .Environment }}"
    input.clientID == "{{ .ClientID }}"
    input.apiName == "{{ .ApiName }}"
    input.apiVersion == "{{ .ApiVersion }}"
    actions_allowed(input.action)
    attributes_allowed(input.attributes)
}

# Validate if the requested action is allowed
actions_allowed(action) {
    allowed_actions := { "{{ range .AllowedActions }}"{{ . }}"{{ end }}" }
    action == allowed_actions[_]
}

# Validate if all requested attributes are allowed
attributes_allowed(requested) {
    count(requested) == count({attr | attr := requested[_]; attr_allowed(attr)})
}

# Helper to check individual attribute
attr_allowed(attr) {
    allowed_attrs := { "{{ range .AllowedAttributes }}"{{ . }}"{{ end }}" }
    attr == allowed_attrs[_]
}
