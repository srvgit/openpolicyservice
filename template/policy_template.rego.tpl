package api.access

import rego.v1

default allow = false

# Main rule to determine if access should be allowed

allow if {
    allowed_client
    allowed_client_application
    allowed_client_application_attributes
}

allowed_client if 

allow {
    # Dynamically unmarshal the allowed actions and attributes at the point of use
    allowed_actions := json.unmarshal({{.AllowedActionsJSON}})
    allowed_attrs := json.unmarshal({{.AllowedAttributesJSON}})
    
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
    allowed_actions := json.unmarshal({{.AllowedActionsJSON}})
    action == allowed_actions[_]
}
    
    # Validate if all requested attributes are allowed
attributes_allowed(requested) {
allowed_attrs := json.unmarshal({{.AllowedAttributesJSON}})
count(requested) == count({attr | attr := requested[_]; attr_allowed(attr)})
}

# Helper to check individual attribute
attr_allowed(attr) {
allowed_attrs := json.unmarshal({{ .AllowedAttributesJSON }})
attr == allowed_attrs[_]
}
