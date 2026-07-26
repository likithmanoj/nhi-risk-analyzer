from nhi.aws import iam

def create_inventory():
    users = iam.list_users()
    roles = iam.list_roles()
    groups = iam.list_groups()

    return {
        "users": users,
        "roles": roles,
        "groups": groups
    }