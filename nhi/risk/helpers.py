def classify_resource(resource):
    if not isinstance(resource, str):
        return None
    if resource == "*" or resource == "arn:aws:*:*:*:*":
        return "UNCONSTRAINED"
    if "*" in resource:
        if resource.startswith("arn:aws:") and not resource.startswith("arn:aws:*:"):
            return "SCOPED_PREFIX"
        return "UNCONSTRAINED"
    return "SPECIFIC"

def analyze_resources(resources):
    resource_findings = []
    if isinstance(resources, str):
        resources_list = [resources]
    elif isinstance(resources, list):
        resources_list = resources
    else:
        return resource_findings

    for resource in resources_list:
        classification = classify_resource(resource)
        if classification in ("UNCONSTRAINED", "SCOPED_PREFIX"):
            resource_findings.append({"Resource": resource, "Type": classification})
            break

    return resource_findings