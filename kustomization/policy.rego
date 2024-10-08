package app.abac.mckinsey

default allow := false

allow {
    app_is_registered
    is_subset(input.application.resources[0].fields, data.policies[input.application.name][input.application.resources[0].apiname].fields)
}

app_is_registered {
    data.policies[input.application.name].allow == true
}

is_subset(input_fields, allowed_fields) {
    # Ensure all input fields are in the allowed fields
    every field in input_fields {
        field == allowed_field |
        allowed_field := allowed_fields[_]
    }
}
